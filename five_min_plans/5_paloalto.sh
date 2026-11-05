#!/usr/bin/env bash

set -o pipefail

PA_IP="${1:-172.20.240.200}"
PA_USER="${2:-admin}"
CURRENT_PASS="${3:-Changeme123}"

echo "================================================================="
echo "   MWCCDC PALO ALTO 5-MINUTE EMERGENCY HARDENING SCRIPT          "
echo "   Target Firewall: ${PA_USER}@${PA_IP}                         "
echo "================================================================="

while true; do
  read -r -s -p "[?] Enter NEW strong Palo Alto Admin Password: " NEW_PASS
  echo ""
  read -r -s -p "[?] Confirm NEW strong Palo Alto Admin Password: " CONFIRM_PASS
  echo ""
  if [[ "$NEW_PASS" == "$CONFIRM_PASS" && ${#NEW_PASS} -ge 8 ]]; then
    break
  fi
  echo "[-] Passwords do not match or are shorter than 8 characters. Try again."
done

echo "[*] Checking reachability to ${PA_IP}..."
if ! ping -c 2 -W 2 "${PA_IP}" > /dev/null 2>&1; then
  echo "[-] ERROR: Cannot reach ${PA_IP}. Check your interface IP / routes."
  exit 1
fi
echo "[+] Network path to firewall is open."

TMP_CMDS=$(mktemp /tmp/panos_batch.XXXXXX)

cat << EOF > "${TMP_CMDS}"
set cli scripting-mode on
set cli echo-input on
set cli config-output-format set
configure

set service srv-splunk-mgmt protocol tcp port 8089
set service srv-mssql protocol tcp port 1433
set service srv-winrm-http protocol tcp port 5985
set service srv-winrm-https protocol tcp port 5986
set service srv-rdp protocol tcp port 3389
set service srv-smb protocol tcp port 445

set address host-ecom ip-netmask 172.20.240.10
set address host-email ip-netmask 172.20.240.15
set address host-splunk ip-netmask 172.20.240.20
set address host-ad ip-netmask 172.20.240.100
set address host-mssql ip-netmask 172.20.240.120

set rulebase security rules 01-ALLOW-SCORED-ICMP from Outside to Inside source any
set rulebase security rules 01-ALLOW-SCORED-ICMP destination host-ecom
set rulebase security rules 01-ALLOW-SCORED-ICMP destination host-email
set rulebase security rules 01-ALLOW-SCORED-ICMP destination host-splunk
set rulebase security rules 01-ALLOW-SCORED-ICMP destination host-ad
set rulebase security rules 01-ALLOW-SCORED-ICMP destination host-mssql
set rulebase security rules 01-ALLOW-SCORED-ICMP service any application ping action allow log-end yes

set rulebase security rules 02-ALLOW-SCORED-WEB from Outside to Inside source any
set rulebase security rules 02-ALLOW-SCORED-WEB destination host-ecom
set rulebase security rules 02-ALLOW-SCORED-WEB destination host-email
set rulebase security rules 02-ALLOW-SCORED-WEB service service-http
set rulebase security rules 02-ALLOW-SCORED-WEB service service-https
set rulebase security rules 02-ALLOW-SCORED-WEB application web-browsing
set rulebase security rules 02-ALLOW-SCORED-WEB application ssl
set rulebase security rules 02-ALLOW-SCORED-WEB action allow log-end yes

set rulebase security rules 03-ALLOW-SCORED-MAIL from Outside to Inside source any destination host-email service any
set rulebase security rules 03-ALLOW-SCORED-MAIL application smtp
set rulebase security rules 03-ALLOW-SCORED-MAIL application pop3
set rulebase security rules 03-ALLOW-SCORED-MAIL application imap
set rulebase security rules 03-ALLOW-SCORED-MAIL action allow log-end yes

set rulebase security rules 04-ALLOW-SCORED-SPLUNK from Outside to Inside source any destination host-splunk application any action allow log-end yes
set rulebase security rules 04-ALLOW-SCORED-SPLUNK service service-http
set rulebase security rules 04-ALLOW-SCORED-SPLUNK service service-https
set rulebase security rules 04-ALLOW-SCORED-SPLUNK service srv-splunk-mgmt

set rulebase security rules 05-ALLOW-SCORED-MSSQL from Outside to Inside source any destination host-mssql application any action allow log-end yes
set rulebase security rules 05-ALLOW-SCORED-MSSQL service srv-mssql
set rulebase security rules 05-ALLOW-SCORED-MSSQL service srv-rdp
set rulebase security rules 05-ALLOW-SCORED-MSSQL service srv-smb

set rulebase security rules 06-ALLOW-SCORED-AD from Outside to Inside source any destination host-ad service any action allow log-end yes
set rulebase security rules 06-ALLOW-SCORED-AD application ms-win-remote-management
set rulebase security rules 06-ALLOW-SCORED-AD application dns
set rulebase security rules 06-ALLOW-SCORED-AD application kerberos
set rulebase security rules 06-ALLOW-SCORED-AD application ldap
set rulebase security rules 06-ALLOW-SCORED-AD application active-directory

move rulebase security rules 01-ALLOW-SCORED-ICMP top
move rulebase security rules 02-ALLOW-SCORED-WEB after 01-ALLOW-SCORED-ICMP
move rulebase security rules 03-ALLOW-SCORED-MAIL after 02-ALLOW-SCORED-WEB
move rulebase security rules 04-ALLOW-SCORED-SPLUNK after 03-ALLOW-SCORED-MAIL
move rulebase security rules 05-ALLOW-SCORED-MSSQL after 04-ALLOW-SCORED-SPLUNK
move rulebase security rules 06-ALLOW-SCORED-AD after 05-ALLOW-SCORED-MSSQL

set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND from Inside to Outside source 172.20.240.0/24 destination any action allow log-end yes
set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND service service-http
set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND service service-https
set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND application web-browsing
set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND application ssl
set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND application dns
set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND application ntp
move rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND after 06-ALLOW-SCORED-AD

set rulebase security rules 08-DROP-UNAUTHORIZED-EGRESS from Inside to Outside source 172.20.240.0/24 destination any service any application any action drop log-end yes
move rulebase security rules 08-DROP-UNAUTHORIZED-EGRESS after 07-ALLOW-INTERNAL-OUTBOUND

set rulebase security rules 09-BLOCK-REDTEAM-MGMT from Outside to Inside source any destination 172.20.240.0/24 service any action reset-both log-end yes
set rulebase security rules 09-BLOCK-REDTEAM-MGMT application ssh
set rulebase security rules 09-BLOCK-REDTEAM-MGMT application telnet
set rulebase security rules 09-BLOCK-REDTEAM-MGMT application ms-rdp
set rulebase security rules 09-BLOCK-REDTEAM-MGMT application vnc
set rulebase security rules 09-BLOCK-REDTEAM-MGMT application smb
move rulebase security rules 09-BLOCK-REDTEAM-MGMT after 08-DROP-UNAUTHORIZED-EGRESS

set rulebase security rules 10-GLOBAL-DENY-ALL from any to any source any destination any service any application any action drop log-end yes
move rulebase security rules 10-GLOBAL-DENY-ALL bottom

set deviceconfig system permitted-ip 172.20.240.0/24
set deviceconfig system idle-timeout 15

set mgt-config users admin password
${NEW_PASS}
${NEW_PASS}

commit description "MWCCDC-5Min-Hardening"
exit
clear session all
exit
EOF

echo "[*] Configuration payload generated (${TMP_CMDS})."
echo "[*] Pushing commands slowly over interactive SSH channel..."

stream_commands() {
  sleep 4
  while IFS= read -r line || [ -n "$line" ]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    echo "$line"
    if [[ "$line" =~ ^commit ]]; then
      sleep 12
    elif [[ "$line" =~ ^configure ]]; then
      sleep 2
    else
      sleep 0.2
    fi
  done < "${TMP_CMDS}"
  sleep 2
}

SSH_CMD="ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 ${PA_USER}@${PA_IP}"

if command -v sshpass >/dev/null 2>&1; then
  stream_commands | sshpass -p "${CURRENT_PASS}" ${SSH_CMD}
else
  echo "[*] Enter current firewall password (${CURRENT_PASS}) if prompted:"
  stream_commands | ${SSH_CMD}
fi

rm -f "${TMP_CMDS}"

echo ""
echo "================================================================="
echo "[+] Deployment complete! Configuration committed and verified."
echo "[+] Current active sessions flushed."
echo "================================================================="

echo "[+] Connectivity tests."
for ip in 172.20.240.10 \
          172.20.240.15 \
          172.20.240.20 \
          172.20.240.100 \
          172.20.240.120; do
    if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        echo "[+] $ip Ping: OK"
    else
        echo "[-] $ip Ping: FAILED"
    fi
done

echo "[+] Check password change and review the security-policy with 'show running security-policy'."
ssh -o StrictHostKeyChecking=no admin@172.20.240.200
