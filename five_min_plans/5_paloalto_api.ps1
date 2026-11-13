param(
    [string]$PA_IP = "172.20.240.200",
    [string]$PA_USER = "admin",
    [string]$CURRENT_PASS = "Changeme123"
)

$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BACKUP_XML = "fw_running_config_$Timestamp.xml"
$BACKUP_TXT = "fw_baseline_state_$Timestamp.txt"

Write-Host "================================================================="
Write-Host "   MWCCDC PALO ALTO: NATIVE HTTPS XML API HARDENER (WIN 7+)      "
Write-Host "================================================================="

# 1. Bypass self-signed SSL certificates & enable TLS 1.0/1.1/1.2 for Windows 7
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]3072 -bor [System.Net.SecurityProtocolType]768 -bor [System.Net.SecurityProtocolType]192

# 2. Prompt for Internal Subnet & New Admin Password
$DEFAULT_SUBNET = "172.20.240.0/24"
$INPUT_SUBNET = Read-Host "[?] Enter Internal Subnet CIDR [Default: $DEFAULT_SUBNET]"
if ([string]::IsNullOrEmpty($INPUT_SUBNET)) { $INTERNAL_SUBNET = $DEFAULT_SUBNET } else { $INTERNAL_SUBNET = $INPUT_SUBNET }
$Splits = $INTERNAL_SUBNET.Split('.')
$BASE_OCTETS = "$($Splits[0]).$($Splits[1]).$($Splits[2])"

while ($true) {
    $SecPass1 = Read-Host "[?] Enter NEW strong Palo Alto Admin Password" -AsSecureString
    $SecPass2 = Read-Host "[?] Confirm NEW strong Palo Alto Admin Password" -AsSecureString
    $NEW_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecPass1))
    $CONFIRM_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecPass2))
    
    if (($NEW_PASS -eq $CONFIRM_PASS) -and ($NEW_PASS.Length -ge 8)) { break }
    Write-Host "[-] Passwords do not match or are too short (minimum 8 chars)." -ForegroundColor Red
}

# 3. Verify Port 443 is accepting connections
Write-Host "[*] Verifying HTTPS port 443 is accepting connections on $PA_IP..."
while ($true) {
    $Tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $Tcp.Connect($PA_IP, 443)
        if ($Tcp.Connected) { $Tcp.Close(); break }
    } catch {
        Start-Sleep -Seconds 2
    }
}
Write-Host "[+] Port 443 open." -ForegroundColor Green

# 4. Helper Functions for PAN-OS XML API (POST method handles large XML payloads safely)
function Invoke-PanApi ([hashtable]$Params) {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $Pairs = @()
    foreach ($k in $Params.Keys) {
        $Pairs += "$([uri]::EscapeDataString($k))=$([uri]::EscapeDataString($Params[$k]))"
    }
    $Body = [string]::Join("&", $Pairs)
    $RawXml = $wc.UploadString("https://$PA_IP/api/", "POST", $Body)
    return [xml]$RawXml
}

# 5. Generate API Key
Write-Host "[*] Authenticating to PAN-OS XML API..."
$KeyXml = Invoke-PanApi @{
    type     = "keygen"
    user     = $PA_USER
    password = $CURRENT_PASS
}
if ($KeyXml.response.status -ne "success") {
    throw "[-] Failed to authenticate to API: $($KeyXml.OuterXml)"
}
$API_KEY = $KeyXml.response.result.key
Write-Host "[+] API Key acquired successfully." -ForegroundColor Green

function Invoke-PanOp ([string]$CmdXml) {
    return Invoke-PanApi @{
        type = "op"
        cmd  = $CmdXml
        key  = $API_KEY
    }
}

function Set-PanConfig ([string]$Action, [string]$XPath, [string]$Element) {
    $Res = Invoke-PanApi @{
        type    = "config"
        action  = $Action
        xpath   = $XPath
        element = $Element
        key     = $API_KEY
    }
    if ($Res.response.status -ne "success") {
        Write-Host "[-] API Warning on $XPath : $($Res.OuterXml)" -ForegroundColor Yellow
    }
}

function Remove-PanConfig ([string]$XPath) {
    $null = Invoke-PanApi @{
        type   = "config"
        action = "delete"
        xpath  = $XPath
        key    = $API_KEY
    }
}

# =================================================================
# PHASE 1: OBSERVE & BACKUP
# =================================================================
Write-Host "[*] PHASE 1: Saving on-box snapshot ('baseline-start') & exporting backups..."

# Save on-box snapshot
$null = Invoke-PanOp "<save><config><to>baseline-start</to></config></save>"

# Export full running XML config locally
$wcExport = New-Object System.Net.WebClient
$wcExport.DownloadFile("https://$PA_IP/api/?type=export&category=configuration&key=$([uri]::EscapeDataString($API_KEY))", ".\$BACKUP_XML")

# Collect operational state into text file for inject documentation
$OpReport = @()
$OpQueries = @(
    "<show><system><info></info></system></show>",
    "<show><clock></clock></show>",
    "<show><high-availability><state></state></high-availability></show>",
    "<show><administrators></administrators></show>",
    "<show><interface>all</interface></show>",
    "<show><zone>all</zone></show>",
    "<show><routing><route></route></routing></show>",
    "<show><running><security-policy></security-policy></running></show>",
    "<show><running><nat-policy></nat-policy></running></show>",
    "<show><session><all></all></session></show>"
)
foreach ($q in $OpQueries) {
    $r = Invoke-PanOp $q
    $OpReport += "=== QUERY: $q ==="
    $OpReport += $r.OuterXml
    $OpReport += ""
}
$OpReport | Out-File -FilePath ".\$BACKUP_TXT" -Encoding UTF8
Write-Host "[+] Backups saved to $BACKUP_XML, $BACKUP_TXT, and on-box as 'baseline-start'." -ForegroundColor Green

# =================================================================
# PHASE 2: HARDENING & SPLUNK DEPLOYMENT
# =================================================================
Write-Host "[*] PHASE 2: Staging Hardening Configuration via XML API..."

$DEV_PATH  = "/config/devices/entry[@name='localhost.localdomain']"
$VSYS_PATH = "$DEV_PATH/vsys/entry[@name='vsys1']"
$NET_PATH  = "$DEV_PATH/network"

# 1. Ask firewall to generate PAN-OS phash for NEW_PASS (Replaces Linux openssl)
$EscapedPass = [System.Security.SecurityElement]::Escape($NEW_PASS)
$HashXml = Invoke-PanOp "<request><password-hash><password>$EscapedPass</password></password-hash></request>"
$ADMIN_HASH = $HashXml.response.result.'phash'
if ([string]::IsNullOrEmpty($ADMIN_HASH)) {
    throw "[-] Could not retrieve password hash from firewall."
}

# 2. Interfaces & Zones
Write-Host "    -> Configuring Interfaces, Zones, and Virtual Router..."
Set-PanConfig "set" "$NET_PATH/interface/ethernet/entry[@name='ethernet1/1']/layer3/ip" "<entry name='172.16.0.1/24'/>"
Set-PanConfig "set" "$NET_PATH/interface/ethernet/entry[@name='ethernet1/2']/layer3/ip" "<entry name='$BASE_OCTETS.254/24'/>"
Set-PanConfig "set" "$VSYS_PATH/zone/entry[@name='Outside']/network/layer3" "<member>ethernet1/1</member>"
Set-PanConfig "set" "$VSYS_PATH/zone/entry[@name='Inside']/network/layer3" "<member>ethernet1/2</member>"
Set-PanConfig "set" "$NET_PATH/virtual-router/entry[@name='default']/interface" "<member>ethernet1/1</member><member>ethernet1/2</member>"

# 3. Clean Static Default Route
$VR_ROUTE_PATH = "$NET_PATH/virtual-router/entry[@name='default']/routing-table/ip/static-route"
Remove-PanConfig "$VR_ROUTE_PATH/entry[@name='default-to-vyos']"
Remove-PanConfig "$VR_ROUTE_PATH/entry[@name='default']"
Remove-PanConfig "$VR_ROUTE_PATH/entry[@name='Def-to-Vyos']"

$RouteElement = @"
<entry name='default'>
  <interface>ethernet1/1</interface>
  <destination>0.0.0.0/0</destination>
  <nexthop><ip-address>172.16.0.254</ip-address></nexthop>
  <metric>5</metric>
</entry>
"@
Set-PanConfig "edit" "$VR_ROUTE_PATH/entry[@name='default']" $RouteElement

# 4. Service Objects
Write-Host "    -> Creating Service & Address Objects..."
$ServicesElement = @"
<entry name='srv-splunk-mgmt'><protocol><tcp><port>8089</port></tcp></protocol></entry>
<entry name='srv-splunk-fwd'><protocol><tcp><port>9997</port></tcp></protocol></entry>
<entry name='srv-syslog-udp'><protocol><udp><port>514</port></udp></protocol></entry>
<entry name='srv-mssql'><protocol><tcp><port>1433</port></tcp></protocol></entry>
<entry name='srv-winrm-http'><protocol><tcp><port>5985</port></tcp></protocol></entry>
<entry name='srv-winrm-https'><protocol><tcp><port>5986</port></tcp></protocol></entry>
<entry name='srv-rdp'><protocol><tcp><port>3389</port></tcp></protocol></entry>
<entry name='srv-smb'><protocol><tcp><port>445</port></tcp></protocol></entry>
<entry name='srv-ftp'><protocol><tcp><port>21</port></tcp></protocol></entry>
<entry name='srv-ssh'><protocol><tcp><port>22</port></tcp></protocol></entry>
"@
Set-PanConfig "set" "$VSYS_PATH/service" $ServicesElement

# 5. Address & Dynamic Attacker Group Objects
$AddressesElement = @"
<entry name='host-ecom'><ip-netmask>$BASE_OCTETS.10</ip-netmask></entry>
<entry name='host-email'><ip-netmask>$BASE_OCTETS.15</ip-netmask></entry>
<entry name='host-splunk'><ip-netmask>$BASE_OCTETS.20</ip-netmask></entry>
<entry name='host-ad'><ip-netmask>$BASE_OCTETS.100</ip-netmask></entry>
<entry name='host-mssql'><ip-netmask>$BASE_OCTETS.120</ip-netmask></entry>
<entry name='net-internal'><ip-netmask>$INTERNAL_SUBNET</ip-netmask></entry>
<entry name='PLACEHOLDER-NULL'><ip-netmask>192.0.2.1/32</ip-netmask></entry>
"@
Set-PanConfig "set" "$VSYS_PATH/address" $AddressesElement
Set-PanConfig "set" "$VSYS_PATH/address-group/entry[@name='ATTACKER-IPS']/static" "<member>PLACEHOLDER-NULL</member>"

# 6. Security Rulebase (Using 'edit' on the rules container replaces pre-existing allow-all rules and preserves exact order 00-99)
Write-Host "    -> Staging Ordered Security Policy Rulebase (00 through 99)..."
$RulesXml = @"
<rules>
  <entry name='00-BLOCK-ATTACKER-IPS'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>ATTACKER-IPS</member></source><destination><member>net-internal</member></destination>
    <application><member>any</member></application><service><member>any</member></service>
    <action>deny</action><log-end>yes</log-end>
  </entry>
  <entry name='01-ALLOW-SCORED-ICMP'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>net-internal</member></destination>
    <application><member>ping</member></application><service><member>any</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='02-ALLOW-SCORED-WEB'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>host-ecom</member><member>host-email</member></destination>
    <application><member>web-browsing</member><member>ssl</member></application>
    <service><member>service-http</member><member>service-https</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='03-ALLOW-SCORED-MAIL'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>host-email</member></destination>
    <application><member>smtp</member><member>pop3</member><member>imap</member></application>
    <service><member>any</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='04-ALLOW-SCORED-SPLUNK'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>host-splunk</member></destination>
    <application><member>any</member></application>
    <service><member>service-http</member><member>service-https</member><member>srv-splunk-mgmt</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='05-ALLOW-SCORED-MSSQL'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>host-mssql</member></destination>
    <application><member>any</member></application>
    <service><member>srv-mssql</member><member>srv-rdp</member><member>srv-smb</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='06-ALLOW-SCORED-AD'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>host-ad</member></destination>
    <application><member>dns</member><member>kerberos</member><member>ldap</member><member>active-directory</member><member>msrpc</member></application>
    <service><member>any</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='07-ALLOW-SCORED-FTP'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source>
    <destination><member>host-ecom</member><member>host-email</member><member>host-splunk</member><member>host-ad</member><member>host-mssql</member></destination>
    <application><member>ftp</member></application><service><member>srv-ftp</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='08-ALLOW-SCORED-SSH'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source>
    <destination><member>host-ecom</member><member>host-email</member><member>host-splunk</member><member>host-ad</member><member>host-mssql</member></destination>
    <application><member>ssh</member></application><service><member>srv-ssh</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='09-ALLOW-SCORED-WINRM'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>host-ad</member></destination>
    <application><member>any</member></application>
    <service><member>srv-winrm-http</member><member>srv-winrm-https</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='10-ALLOW-OUTBOUND-DNS'>
    <from><member>Inside</member></from><to><member>Outside</member></to>
    <source><member>net-internal</member></source><destination><member>any</member></destination>
    <application><member>dns</member></application><service><member>application-default</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='11-ALLOW-OUTBOUND-WEB'>
    <from><member>Inside</member></from><to><member>Outside</member></to>
    <source><member>net-internal</member></source><destination><member>any</member></destination>
    <application><member>any</member></application>
    <service><member>service-http</member><member>service-https</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='12-ALLOW-OUTBOUND-PING'>
    <from><member>Inside</member></from><to><member>Outside</member></to>
    <source><member>net-internal</member></source><destination><member>any</member></destination>
    <application><member>ping</member></application><service><member>any</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='13-ALLOW-OUTBOUND-NTP'>
    <from><member>Inside</member></from><to><member>Outside</member></to>
    <source><member>net-internal</member></source><destination><member>any</member></destination>
    <application><member>ntp</member></application><service><member>application-default</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='14-BLOCK-UNAUTH-EGRESS'>
    <from><member>Inside</member></from><to><member>Outside</member></to>
    <source><member>net-internal</member></source><destination><member>any</member></destination>
    <application><member>any</member></application><service><member>any</member></service>
    <action>drop</action><log-end>yes</log-end>
  </entry>
  <entry name='15-BLOCK-REDTEAM-MGMT'>
    <from><member>Outside</member></from><to><member>Inside</member></to>
    <source><member>any</member></source><destination><member>net-internal</member></destination>
    <application><member>ssh</member><member>telnet</member><member>ms-rdp</member><member>vnc</member><member>ms-ds-smb</member></application>
    <service><member>any</member></service>
    <action>reset-both</action><log-end>yes</log-end>
  </entry>
  <entry name='16-ALLOW-INTRA-AD'>
    <from><member>Inside</member></from><to><member>Inside</member></to>
    <source><member>net-internal</member></source><destination><member>host-ad</member></destination>
    <application><member>dns</member><member>kerberos</member><member>ldap</member><member>active-directory</member><member>msrpc</member><member>ms-ds-smb</member><member>ping</member></application>
    <service><member>any</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='17-ALLOW-INTRA-SPLUNK'>
    <from><member>Inside</member></from><to><member>Inside</member></to>
    <source><member>net-internal</member></source><destination><member>host-splunk</member></destination>
    <application><member>any</member></application>
    <service><member>srv-splunk-fwd</member><member>srv-syslog-udp</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='18-ALLOW-INTRA-MSSQL'>
    <from><member>Inside</member></from><to><member>Inside</member></to>
    <source><member>host-ecom</member></source><destination><member>host-mssql</member></destination>
    <application><member>any</member></application><service><member>srv-mssql</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='19-ALLOW-INTRA-MAIL'>
    <from><member>Inside</member></from><to><member>Inside</member></to>
    <source><member>net-internal</member></source><destination><member>host-email</member></destination>
    <application><member>smtp</member><member>pop3</member><member>imap</member><member>web-browsing</member><member>ssl</member></application>
    <service><member>any</member></service>
    <action>allow</action><log-end>yes</log-end>
  </entry>
  <entry name='99-GLOBAL-DENY-ALL'>
    <from><member>any</member></from><to><member>any</member></to>
    <source><member>any</member></source><destination><member>any</member></destination>
    <application><member>any</member></application><service><member>any</member></service>
    <action>drop</action><log-end>yes</log-end>
  </entry>
</rules>
"@
Set-PanConfig "edit" "$VSYS_PATH/rulebase/security/rules" $RulesXml

# 7. Splunk Syslog Forwarding (System, Config, Traffic)
Write-Host "    -> Configuring Splunk Syslog Forwarding (TCP 9997)..."
$SyslogServerXml = @"
<entry name='Splunk-Server'>
  <server>
    <entry name='Splunk-Node'>
      <server>$BASE_OCTETS.20</server>
      <transport>TCP</transport>
      <port>9997</port>
      <format>BSD</format>
      <facility>LOG_LOCAL7</facility>
    </entry>
  </server>
</entry>
"@
Set-PanConfig "edit" "/config/shared/log-settings/syslog/entry[@name='Splunk-Server']" $SyslogServerXml
Set-PanConfig "set" "/config/shared/log-settings/system/match-list/entry[@name='Splunk-Sys']" "<filter>All Logs</filter><send-syslog><member>Splunk-Server</member></send-syslog>"
Set-PanConfig "set" "/config/shared/log-settings/config/match-list/entry[@name='Splunk-Cfg']" "<filter>All Logs</filter><send-syslog><member>Splunk-Server</member></send-syslog>"
Set-PanConfig "set" "/config/shared/log-settings/traffic/match-list/entry[@name='Splunk-Tfc']" "<filter>All Logs</filter><send-syslog><member>Splunk-Server</member></send-syslog>"

# 8. Management Permitted IP & Admin Password Hash
Write-Host "    -> Hardening Management Interface & Admin Password..."
Set-PanConfig "set" "$DEV_PATH/deviceconfig/system/permitted-ip" "<entry name='$INTERNAL_SUBNET'/>"
Set-PanConfig "edit" "/config/mgt-config/users/entry[@name='admin']/phash" "<phash>$ADMIN_HASH</phash>"

# 9. Save Post-Rules Snapshot
$null = Invoke-PanOp "<save><config><to>post-rules-pre-delete</to></config></save>"

Write-Host ""
Write-Host "=======================================================================" -ForegroundColor Cyan
Write-Host " [!] PAYLOAD STAGED VIA XML API! saved as 'post-rules-pre-delete' [!]  " -ForegroundColor Cyan
Write-Host "=======================================================================" -ForegroundColor Cyan
Write-Host " Because 'action=edit' was used on the security rules node, any old"
Write-Host " default rules (like 'Permit Inbound') have already been cleanly replaced!"
Write-Host ""
Write-Host " To commit immediately from PowerShell, run:"
Write-Host "   Invoke-WebRequest / WebClient against:"
Write-Host "   https://$PA_IP/api/?type=commit&cmd=<commit><description>MWCCDC-Harden-With-Splunk</description></commit>&key=$API_KEY"
Write-Host ""
Write-Host " Or open https://$PA_IP in your browser (or NETLAB+ PAN console) and run:"
Write-Host "   configure"
Write-Host "   commit description `"MWCCDC-Harden-With-Splunk`""
Write-Host "======================================================================="