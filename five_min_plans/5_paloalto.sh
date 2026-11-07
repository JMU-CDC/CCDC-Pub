#!/usr/bin/env bash
set -o pipefail

PA_IP="${1:-172.20.240.200}"
PA_USER="${2:-admin}"
CURRENT_PASS="${3:-Changeme123}"
BACKUP_FILE="fw_baseline_$(date +%Y%m%d_%H%M%S).txt"

echo "================================================================="
echo "   MWCCDC PALO ALTO: OBSERVE, BACKUP & HARDEN                    "
echo "================================================================="

DEFAULT_SUBNET="172.20.240.0/24"
read -r -p "[?] Enter Internal Subnet CIDR [Default: ${DEFAULT_SUBNET}]: " INPUT_SUBNET
INTERNAL_SUBNET="${INPUT_SUBNET:-$DEFAULT_SUBNET}"
BASE_OCTETS=$(echo "${INTERNAL_SUBNET}" | cut -d'.' -f1-3)

while true; do
  read -r -s -p "[?] Enter NEW strong Palo Alto Admin Password: " NEW_PASS
  echo ""
  read -r -s -p "[?] Confirm NEW strong Palo Alto Admin Password: " CONFIRM_PASS
  echo ""
  if [[ "$NEW_PASS" == "$CONFIRM_PASS" && ${#NEW_PASS} -ge 8 ]]; then break; fi
  echo "[-] Passwords do not match or are too short."
done

echo "[*] Verifying port 22 is accepting connections..."
until timeout 2 bash -c "</dev/tcp/${PA_IP}/22" >/dev/null 2>&1; do
  sleep 2
done
echo "[+] Port 22 open."

# =================================================================
# PHASE 1: OBSERVE & BACKUP
# =================================================================
echo "[*] PHASE 1: Executing Observe & Backup (Saving to ${BACKUP_FILE})..."

observe_and_backup() {
  sleep 6
  echo "set cli scripting-mode on"
  sleep 0.5
  
  # Gather interface, zone, routing, and NAT intelligence
  echo "show interface all"
  sleep 0.5
  echo "show zone all"
  sleep 0.5
  echo "show routing route"
  sleep 0.5
  echo "show running nat-policy"
  sleep 0.5
  
  # Capture active scoring or Red Team connections prior to dropping
  echo "show session all"
  sleep 0.5
  
  # Capture the formatted, active security policy
  echo "show running security-policy"
  sleep 0.5
  
  # Dump the raw configuration commands
  echo "set cli config-output-format set"
  sleep 0.5
  echo "configure"
  sleep 2
  echo "show"
  sleep 5
  echo "exit"
  sleep 0.5
  echo "exit"
  sleep 1
}

SSH_CMD="ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${PA_USER}@${PA_IP}"

if command -v sshpass >/dev/null 2>&1; then
  observe_and_backup | sshpass -p "${CURRENT_PASS}" ${SSH_CMD} > "${BACKUP_FILE}" 2>/dev/null
else
  echo "[!] sshpass not found. You will be prompted for the CURRENT password TWICE (once for backup, once for hardening)."
  observe_and_backup | ${SSH_CMD} > "${BACKUP_FILE}" 2>/dev/null
fi

echo "[+] Baseline configuration and state saved to ${BACKUP_FILE}"

# =================================================================
# PHASE 2: HARDENING & SPLUNK DEPLOYMENT
# =================================================================
echo "[*] PHASE 2: Generating Hardening Payload..."

TMP_CMDS=$(mktemp /tmp/panos_batch.XXXXXX)

cat << EOF > "${TMP_CMDS}"
set cli scripting-mode on
set cli echo-input on
set cli config-output-format set
configure

# Interface & Zone Bindings
set network interface ethernet ethernet1/1 layer3 ip 172.16.0.1/24
set network interface ethernet ethernet1/2 layer3 ip ${BASE_OCTETS}.254/24
set zone Outside network layer3 ethernet1/1
set zone Inside network layer3 ethernet1/2

# Default Route to VyOS
set network virtual-router default routing-table ip static-route default-to-vyos nexthop ip-address 172.16.0.254
set network virtual-router default routing-table ip static-route default-to-vyos destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route default-to-vyos interface ethernet1/1

# Service & Scored Server Address Objects
set service srv-splunk-mgmt protocol tcp port 8089
set service srv-mssql protocol tcp port 1433
set service srv-winrm-http protocol tcp port 5985
set service srv-winrm-https protocol tcp port 5986
set service srv-rdp protocol tcp port 3389
set service srv-smb protocol tcp port 445

set address host-ecom ip-netmask ${BASE_OCTETS}.10
set address host-email ip-netmask ${BASE_OCTETS}.15
set address host-splunk ip-netmask ${BASE_OCTETS}.20
set address host-ad ip-netmask ${BASE_OCTETS}.100
set address host-mssql ip-netmask ${BASE_OCTETS}.120
set address net-internal ip-netmask ${INTERNAL_SUBNET}

# Ingress Scored Rules
set rulebase security rules 01-ALLOW-SCORED-ICMP from Outside to Inside source any destination [ host-ecom host-email host-splunk host-ad host-mssql ] service any application ping action allow log-end yes
set rulebase security rules 02-ALLOW-SCORED-WEB from Outside to Inside source any destination [ host-ecom host-email ] service [ service-http service-https ] application [ web-browsing ssl ] action allow log-end yes
set rulebase security rules 03-ALLOW-SCORED-MAIL from Outside to Inside source any destination host-email service any application [ smtp pop3 imap ] action allow log-end yes
set rulebase security rules 04-ALLOW-SCORED-SPLUNK from Outside to Inside source any destination host-splunk service [ service-http service-https srv-splunk-mgmt ] application any action allow log-end yes
set rulebase security rules 05-ALLOW-SCORED-MSSQL from Outside to Inside source any destination host-mssql service [ srv-mssql srv-rdp srv-smb ] application any action allow log-end yes
set rulebase security rules 06-ALLOW-SCORED-AD from Outside to Inside source any destination host-ad service any application [ ms-win-remote-management dns kerberos ldap active-directory ] action allow log-end yes

# Outbound Workstation Access & Red Team Drops
set rulebase security rules 07-OUTBOUND-DNS from Inside to Outside source net-internal destination any application dns service default action allow log-end yes
set rulebase security rules 08-OUTBOUND-WEB-DOWNLOADS from Inside to Outside source net-internal destination any service [ service-http service-https ] application [ web-browsing ssl apt-get yum curl wget ] action allow log-end yes
set rulebase security rules 09-BLOCK-UNAUTHORIZED-EGRESS from Inside to Outside source net-internal destination any service any application any action drop log-end yes
set rulebase security rules 10-BLOCK-REDTEAM-MGMT from Outside to Inside source any destination ${INTERNAL_SUBNET} service any application [ ssh telnet ms-rdp vnc smb ] action reset-both log-end yes
set rulebase security rules 11-GLOBAL-DENY-ALL from any to any source any destination any service any application any action drop log-end yes

# Rule Re-ordering
move rulebase security rules 01-ALLOW-SCORED-ICMP top
move rulebase security rules 02-ALLOW-SCORED-WEB after 01-ALLOW-SCORED-ICMP
move rulebase security rules 03-ALLOW-SCORED-MAIL after 02-ALLOW-SCORED-WEB
move rulebase security rules 04-ALLOW-SCORED-SPLUNK after 03-ALLOW-SCORED-MAIL
move rulebase security rules 05-ALLOW-SCORED-MSSQL after 04-ALLOW-SCORED-SPLUNK
move rulebase security rules 06-ALLOW-SCORED-AD after 05-ALLOW-SCORED-MSSQL
move rulebase security rules 07-OUTBOUND-DNS after 06-ALLOW-SCORED-AD
move rulebase security rules 08-OUTBOUND-WEB-DOWNLOADS after 07-OUTBOUND-DNS
move rulebase security rules 09-BLOCK-UNAUTHORIZED-EGRESS after 08-OUTBOUND-WEB-DOWNLOADS
move rulebase security rules 10-BLOCK-REDTEAM-MGMT after 09-BLOCK-UNAUTHORIZED-EGRESS
move rulebase security rules 11-GLOBAL-DENY-ALL bottom

# Outbound NAT
set rulebase nat rules LAN-TO-TRANSIT-NAT from Inside to Outside source net-internal destination any service any to-interface ethernet1/1 source-translation interface-address interface ethernet1/1

# Splunk Forwarding & Auditing (To Local Splunk VM)
set deviceconfig setting management audit-enabled yes
set deviceconfig setting management commit-audit-log yes
set deviceconfig system syslog-server ${BASE_OCTETS}.20 transport tcp port 9997 format default facility local7
set deviceconfig system syslog-server ${BASE_OCTETS}.20 log-type system
set deviceconfig system syslog-server ${BASE_OCTETS}.20 log-type config
set deviceconfig system syslog-server ${BASE_OCTETS}.20 log-type threat
set deviceconfig system syslog-server ${BASE_OCTETS}.20 log-type traffic

# Device Management Hardening
set deviceconfig system permitted-ip ${INTERNAL_SUBNET}
set mgt-config users admin password
${NEW_PASS}
${NEW_PASS}

commit description "MWCCDC-Harden-With-Splunk"
exit
clear session all
exit
EOF

echo "[*] Connecting to firewall to push configuration..."
stream_commands() {
  sleep 6
  echo "set cli scripting-mode on"
  sleep 0.5
  echo "set cli echo-input on"
  sleep 0.5
  echo "set cli config-output-format set"
  sleep 0.5
  echo "configure"
  sleep 3
  while IFS= read -r line || [ -n "$line" ]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    echo "$line"
    if [[ "$line" =~ ^commit ]]; then sleep 12; else sleep 0.5; fi
  done < "${TMP_CMDS}"
  sleep 2
}

if command -v sshpass >/dev/null 2>&1; then
  stream_commands | sshpass -p "${CURRENT_PASS}" ${SSH_CMD}
else
  stream_commands | ${SSH_CMD}
fi

rm -f "${TMP_CMDS}"
echo "[+] Configuration finished, committed, and active sessions cleared."
