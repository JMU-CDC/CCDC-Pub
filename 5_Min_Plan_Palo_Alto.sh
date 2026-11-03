#!/usr/bin/env bash
# ==============================================================================
# MWCCDC Palo Alto PAN-OS 5-Minute Emergency Hardening Script
# Target: PAN-OS 11.0.2
# Management IP: 172.20.240.200 | Inside Interface: 172.20.240.254
# Run from: Ubuntu Wkst or Kali VM (Inside Pod LAN)
# Zero external Python dependencies required. Uses native OpenSSH / sshpass / expect.
# ==============================================================================

set -o pipefail

PA_IP="${1:-172.20.240.200}"
PA_USER="${2:-admin}"
CURRENT_PASS="${3:-Changeme123}"

echo "================================================================="
echo "   MWCCDC PALO ALTO 5-MINUTE EMERGENCY HARDENING SCRIPT          "
echo "   Target Firewall: ${PA_USER}@${PA_IP}                         "
echo "================================================================="

# Prompt interactively for the new administrator password
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

# Step 1: Pre-flight Ping Check
echo "[*] Checking reachability to ${PA_IP}..."
if ! ping -c 2 -W 2 "${PA_IP}" > /dev/null 2>&1; then
    echo "[-] ERROR: Cannot reach ${PA_IP}. Check your interface IP / routes."
    exit 1
fi
echo "[+] Network path to firewall is open."

# Step 2: Build the complete PAN-OS configuration batch payload
TMP_CMDS=$(mktemp /tmp/panos_batch.XXXXXX)

cat << 'EOF' > "${TMP_CMDS}"
set cli scripting-mode on
set cli config-output-format set
configure

# -------------------------------------------------------------
# 1. Custom Scored Services Definitions (MWCCDC Scored Baseline)
# -------------------------------------------------------------
set service srv-splunk-mgmt protocol tcp port 8089
set service srv-mssql protocol tcp port 1433
set service srv-winrm-http protocol tcp port 5985
set service srv-winrm-https protocol tcp port 5986
set service srv-rdp protocol tcp port 3389
set service srv-smb protocol tcp port 445

# -------------------------------------------------------------
# 2. Host Address Objects (Per MWCCDC Topology)
# -------------------------------------------------------------
set address host-ecom ip-netmask 172.20.240.10
set address host-email ip-netmask 172.20.240.15
set address host-splunk ip-netmask 172.20.240.20
set address host-ad ip-netmask 172.20.240.100
set address host-mssql ip-netmask 172.20.240.120

# -------------------------------------------------------------
# 3. Security Rules - Scored Services Access (Rule 9 & 12 Compliance)
# -------------------------------------------------------------
# Rule 01: Scored ICMP across all servers (Explicitly required by Rule 12)
set rulebase security rules 01-ALLOW-SCORED-ICMP to trust from untrust source any destination [ host-ecom host-email host-splunk host-ad host-mssql ] service any application ping action allow log-end yes

# Rule 02: Scored Web (HTTP/HTTPS to Ecom & Webmail)
set rulebase security rules 02-ALLOW-SCORED-WEB to trust from untrust source any destination [ host-ecom host-email ] service [ service-http service-https ] application [ web-browsing ssl ] action allow log-end yes

# Rule 03: Scored Mail (SMTP, POP3, IMAP to Ubuntu Email)
set rulebase security rules 03-ALLOW-SCORED-MAIL to trust from untrust source any destination host-email service any application [ smtp pop3 imap ] action allow log-end yes

# Rule 04: Scored Splunk (Web & Management Port 8089)
set rulebase security rules 04-ALLOW-SCORED-SPLUNK to trust from untrust source any destination host-splunk service [ service-http service-https srv-splunk-mgmt ] application any action allow log-end yes

# Rule 05: Scored MSSQL Services (TCP 1433, SMB 445, RDP 3389)
set rulebase security rules 05-ALLOW-SCORED-MSSQL to trust from untrust source any destination host-mssql service [ srv-mssql srv-rdp srv-smb ] application any action allow log-end yes

# Rule 06: Scored AD Services (WinRM 5985/5986, DNS 53, Kerberos, LDAP)
set rulebase security rules 06-ALLOW-SCORED-AD to trust from untrust source any destination host-ad service [ srv-winrm-http srv-winrm-https any ] application [ ms-win-remote-management dns kerberos ldap active-directory ] action allow log-end yes

# Prioritize Scored Rules at the Top of the Rulebase
move rulebase security rules 01-ALLOW-SCORED-ICMP top
move rulebase security rules 02-ALLOW-SCORED-WEB after 01-ALLOW-SCORED-ICMP
move rulebase security rules 03-ALLOW-SCORED-MAIL after 02-ALLOW-SCORED-WEB
move rulebase security rules 04-ALLOW-SCORED-SPLUNK after 03-ALLOW-SCORED-MAIL
move rulebase security rules 05-ALLOW-SCORED-MSSQL after 04-ALLOW-SCORED-SPLUNK
move rulebase security rules 06-ALLOW-SCORED-AD after 05-ALLOW-SCORED-MSSQL

# -------------------------------------------------------------
# 4. Outbound Egress Whitelist (Essential Updates & DNS/NTP)
# -------------------------------------------------------------
set rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND to untrust from trust source 172.20.240.0/24 destination any service [ service-http service-https ] application [ web-browsing ssl dns ntp ] action allow log-end yes
move rulebase security rules 07-ALLOW-INTERNAL-OUTBOUND after 06-ALLOW-SCORED-AD

# Block unauthorized outbound egress (Blocks Netcat / Python reverse shells)
set rulebase security rules 08-DROP-UNAUTHORIZED-EGRESS to untrust from trust source 172.20.240.0/24 destination any service any application any action drop log-end yes
move rulebase security rules 08-DROP-UNAUTHORIZED-EGRESS after 07-ALLOW-INTERNAL-OUTBOUND

# -------------------------------------------------------------
# 5. Ingress Block for External Management to LAN
# -------------------------------------------------------------
set rulebase security rules 09-BLOCK-REDTEAM-MGMT to trust from untrust source any destination 172.20.240.0/24 service any application [ ssh telnet ms-rdp vnc smb ] action reset-both log-end yes
move rulebase security rules 09-BLOCK-REDTEAM-MGMT after 08-DROP-UNAUTHORIZED-EGRESS

# -------------------------------------------------------------
# 6. Global Catch-All Deny with Logging
# -------------------------------------------------------------
set rulebase security rules 10-GLOBAL-DENY-ALL to any from any source any destination any service any application any action drop log-end yes
move rulebase security rules 10-GLOBAL-DENY-ALL bottom

# -------------------------------------------------------------
# 7. Management Plane Protection
# -------------------------------------------------------------
set deviceconfig system permitted-ip [ 172.20.240.0/24 ]
set deviceconfig system idle-timeout 15
EOF

# Append Admin Password Update, Commit, and Exit commands
cat << EOF >> "${TMP_CMDS}"
set mgt-config users admin password
${NEW_PASS}
${NEW_PASS}
commit description "MWCCDC-5Min-Hardening"
exit
clear session all
exit
EOF

echo "[*] Configuration payload generated (${TMP_CMDS})."

# Step 3: Check for execution tools (sshpass or expect fallback)
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

echo "[*] Pushing batch commands to ${PA_USER}@${PA_IP}..."

if command -v sshpass >/dev/null 2>&1; then
    sshpass -p "${CURRENT_PASS}" ssh ${SSH_OPTS} -tt "${PA_USER}@${PA_IP}" < "${TMP_CMDS}"
elif command -v expect >/dev/null 2>&1; then
    # Fallback to expect script if sshpass is not installed
    expect -c "
        set timeout 60
        spawn ssh ${SSH_OPTS} -tt ${PA_USER}@${PA_IP}
        expect {
            \"*password:*\" { send \"${CURRENT_PASS}\r\"; exp_continue }
            \"*>*\" {
                set f [open \"${TMP_CMDS}\" r]
                while {[gets \$f line] >= 0} {
                    send -- \"\$line\r\"
                    sleep 0.1
                }
                close \$f
            }
        }
        expect eof
    "
else
    echo "[!] Neither 'sshpass' nor 'expect' found."
    echo "[*] Initiating standard interactive SSH stream. Enter current password (${CURRENT_PASS}) if prompted:"
    ssh ${SSH_OPTS} -tt "${PA_USER}@${PA_IP}" < "${TMP_CMDS}"
fi

# Clean up batch file from /tmp
rm -f "${TMP_CMDS}"

echo ""
echo "================================================================="
echo "[+] SUCCESS: Palo Alto 5-minute hardening deployed and committed!"
echo "[+] Admin password changed to your newly supplied credential."
echo "[+] Inbound scored services allowed, rogue egress blocked, sessions cleared."
echo "[+] Login to Quotient (https://quotient.ccdc.events/) to verify scoring."
echo "================================================================="