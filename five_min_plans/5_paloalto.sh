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

# Generate PAN-OS compatible password hash locally to bypass interactive CLI prompt
SALT=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 8 | head -n 1)
ADMIN_HASH=$(openssl passwd -1 -salt "$SALT" "${NEW_PASS}")

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
  echo "[*] Waiting 15 seconds for PAN-OS shell to initialize..." >&2
  sleep 15
  echo ""
  sleep 2
  
  echo "set cli scripting-mode on"
  sleep 1
  
  echo "show interface all"
  sleep 1
  echo "show zone all"
  sleep 1
  echo "show routing route"
  sleep 1
  echo "show running nat-policy"
  sleep 1
  echo "show session all"
  sleep 1
  echo "show running security-policy"
  sleep 1
  
  echo "set cli config-output-format set"
  sleep 1
  echo "configure"
  sleep 3
  echo "show"
  sleep 6
  echo "exit"
  sleep 1
  echo "exit"
  sleep 2
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
# Interface & Zone Bindings
set network interface ethernet ethernet1/1 layer3 ip 172.16.0.1/24
set network interface ethernet ethernet1/2 layer3 ip ${BASE_OCTETS}.254/24
set zone Outside network layer3 ethernet1/1
set zone Inside network layer3 ethernet1/2

# Wipe any existing default routes to prevent "not unique" conflicts
delete network virtual-router default routing-table ip static-route default-to-vyos
delete network virtual-router default routing-table ip static-route default
delete network virtual-router default routing-table ip static-route Def-to-Vyos

# Set the clean Default Route to VyOS using edit mode to bypass line-by-line validation
edit network virtual-router default routing-table ip static-route default
set destination 0.0.0.0/0
set nexthop ip-address 172.16.0.254
set interface ethernet1/1
set metric 5
top

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
set rulebase security rules 06-ALLOW-SCORED-AD from Outside to Inside source any destination host-ad service any application [ dns kerberos ldap active-directory msrpc ] action allow log-end yes

# Outbound Workstation Access & Red Team Drops
set rulebase security rules 07-OUTBOUND-DNS from Inside to Outside source net-internal destination any application dns service application-default action allow log-end yes
set rulebase security rules 08-OUTBOUND-WEB-DOWNLOADS from Inside to Outside source net-internal destination any service [ service-http service-https ] application [ web-browsing ssl ] action allow log-end yes
set rulebase security rules 09-BLOCK-UNAUTHORIZED-EGRESS from Inside to Outside source net-internal destination any service any application any action drop log-end yes
set rulebase security rules 10-BLOCK-REDTEAM-MGMT from Outside to Inside source any destination ${INTERNAL_SUBNET} service any application [ ssh telnet ms-rdp vnc ms-ds-smb ] action reset-both log-end yes
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
set rulebase nat rules LAN-TO-TRANSIT-NAT from Inside to Outside source net-internal destination any service any to-interface ethernet1/1 source-translation dynamic-ip-and-port interface-address interface ethernet1/1

# Splunk Forwarding
set shared log-settings syslog Splunk-Server server Splunk-Node server ${BASE_OCTETS}.20 transport TCP port 9997 format BSD facility LOG_LOCAL7
set shared log-settings system match-list Splunk-Sys filter "All Logs" send-syslog Splunk-Server
set shared log-settings config match-list Splunk-Cfg filter "All Logs" send-syslog Splunk-Server

# Device Management Hardening & Password Set via Hash
set deviceconfig system permitted-ip ${INTERNAL_SUBNET}
set mgt-config users admin phash "${ADMIN_HASH}"

exit
exit
EOF

echo "[*] Connecting to firewall to stage candidate configuration..."
stream_commands() {
  echo "[*] Waiting 15 seconds for PAN-OS shell to initialize..." >&2
  sleep 15
  echo ""
  sleep 2

  echo "set cli scripting-mode on"
  sleep 1
  echo "set cli config-output-format set"
  sleep 1
  echo "configure"
  sleep 4
  
  while IFS= read -r line || [ -n "$line" ]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    echo "$line"
    sleep 1
  done < "${TMP_CMDS}"
  
  sleep 2
}

if command -v sshpass >/dev/null 2>&1; then
  stream_commands | sshpass -p "${CURRENT_PASS}" ${SSH_CMD}
else
  stream_commands | ${SSH_CMD}
fi

rm -f "${TMP_CMDS}"

echo ""
echo "======================================================================="
echo " [!] PAYLOAD STAGED SUCCESSFULLY! MANUAL COMMIT REQUIRED [!] "
echo "======================================================================="
echo " The configuration has been loaded into the candidate config."
echo " To apply these changes and lock down the firewall, you MUST run:"
echo ""
echo "   1. Log into the firewall:"
echo "      ssh admin@${PA_IP}"
echo "      (Use the NEW password you set at the beginning of this script)"
echo ""
echo "   2. Enter config mode:"
echo "      configure"
echo ""
echo "   3. Verify static routes (catch hidden organizer duplicate routes):"
echo "      show network virtual-router default routing-table ip static-route"
echo "      (If any route besides 'default' points to 0.0.0.0/0, delete it!)"
echo "      (Example: delete network virtual-router default routing-table ip static-route Bad-Route)"
echo ""
echo "   4. Commit the changes:"
echo "      commit description \"MWCCDC-Harden\""
echo "======================================================================="
echo ""
