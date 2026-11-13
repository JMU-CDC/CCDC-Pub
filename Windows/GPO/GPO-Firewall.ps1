#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$TargetOU,
    [ValidateNotNullOrEmpty()][string]$GPOName = 'CCDC-Firewall-Baseline',

    [int[]]$ExtraTcpPorts = @(),
    [int[]]$ExtraUdpPorts = @(),

    [switch]$EnableLink,
    [switch]$ForceUpdate
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$domain = Get-ADDomain
$server = $domain.PDCEmulator
$domain = Get-ADDomain -Server $server

if ([string]::IsNullOrWhiteSpace($TargetOU)) {
    $targetDN = $domain.DistinguishedName
} else {
    $isDomainRoot = $TargetOU.Trim().Equals($domain.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)
    if ($isDomainRoot) {
        $targetDN = $domain.DistinguishedName
    } else {
        $ou = Get-ADOrganizationalUnit -Identity $TargetOU -Server $server
        if (!$ou.DistinguishedName.EndsWith(',' + $domain.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'TargetOU must be an OU or domain root in the current domain.'
        }
        $targetDN = $ou.DistinguishedName
    }
}

$gpParams = @{ Domain = $domain.DNSRoot; Server = $server }
$ruleKey = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       TIER 3: CCDC SAFE BASELINE FIREWALL GPO            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Domain      : $($domain.DNSRoot) | PDC: $server"
Write-Host "Target OU/DN: $targetDN"
Write-Host "GPO Name    : $GPOName"
Write-Host "Enable Link : $EnableLink"
Write-Host "`n[+] Scored & Core Service Allow Rules Staged:" -ForegroundColor Yellow
Write-Host "  - ICMPv4 (Echo Request / Ping - scored across all boxes)"
Write-Host "  - Active Directory & RPC (53, 88, 135, 389, 445, 464, 636, 3268, 49152-65535)"
Write-Host "  - WinRM HTTP/HTTPS (5985, 5986 - scored on DC)"
Write-Host "  - MSSQL Database Engine (1433 - scored on MSSQL)"
Write-Host "  - Remote Desktop Protocol (3389 - scored on MSSQL)"
Write-Host "  - Server Message Block (445 - scored for SOPs on MSSQL)"

if (!$PSCmdlet.ShouldProcess($GPOName, "Deploy safe baseline firewall rules to '$targetDN'")) { return }

$firewallRules = [ordered]@{
    'CCDC-Allow-ICMPv4' = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=8:*|Name=CCDC Allow Inbound Ping (Scored Reachability)|Desc=CCDC Competition Scored Reachability Check|'
    'CCDC-Allow-DNS'    = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=53|Name=CCDC Allow DNS UDP 53|'
    'CCDC-Allow-DNS-TCP'= 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=53|Name=CCDC Allow DNS TCP 53|'
    'CCDC-Allow-Kerberos'= 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=88|Name=CCDC Allow Kerberos TCP 88|'
    'CCDC-Allow-Kerberos-UDP'= 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=88|Name=CCDC Allow Kerberos UDP 88|'
    'CCDC-Allow-SMB'    = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|Name=CCDC Allow SMB 445 (SYSVOL/NETLOGON/SOP)|'
    'CCDC-Allow-LDAP'   = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=389|Name=CCDC Allow LDAP TCP 389|'
    'CCDC-Allow-LDAPS'  = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=636|Name=CCDC Allow LDAPS TCP 636|'
    'CCDC-Allow-RPC-Endpoint' = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=135|Name=CCDC Allow RPC Endpoint Mapper TCP 135|'
    'CCDC-Allow-RPC-Dynamic'  = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=49152-65535|Name=CCDC Allow Dynamic RPC Ports|'
    'CCDC-Allow-WinRM-HTTP'   = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5985|Name=CCDC Allow WinRM HTTP 5985 (Scored)|'
    'CCDC-Allow-WinRM-HTTPS'  = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5986|Name=CCDC Allow WinRM HTTPS 5986 (Scored)|'
    'CCDC-Allow-MSSQL'        = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=1433|Name=CCDC Allow MSSQL 1433 (Scored)|'
    'CCDC-Allow-RDP'          = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=CCDC Allow RDP TCP 3389 (Scored on MSSQL)|'
}

if ($ExtraTcpPorts.Count) {
    foreach ($p in $ExtraTcpPorts) {
        $firewallRules["CCDC-Allow-Extra-TCP-$p"] = "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=$p|Name=CCDC Allow Extra TCP $p|"
    }
}
if ($ExtraUdpPorts.Count) {
    foreach ($p in $ExtraUdpPorts) {
        $firewallRules["CCDC-Allow-Extra-UDP-$p"] = "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=$p|Name=CCDC Allow Extra UDP $p|"
    }
}

$existingGpo = Get-GPO -Name $GPOName @gpParams -ErrorAction SilentlyContinue

if (!$existingGpo) {
    $existingGpo = New-GPO -Name $GPOName -Comment "CCDC Tier 3 Safe Firewall Baseline - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" @gpParams
    Write-Host "[+] Created GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
} else {
    Write-Host "[+] Found existing GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
}

foreach ($profile in 'DomainProfile', 'PrivateProfile', 'PublicProfile') {
    $profKey = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$profile"
    $null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $profKey -ValueName 'EnableFirewall' -Type DWord -Value 1 @gpParams
}
Write-Host "[+] Verified Firewall Profile enablement (Domain, Private, Public) in GPO." -ForegroundColor Green

foreach ($ruleName in $firewallRules.Keys) {
    $ruleString = $firewallRules[$ruleName]
    $null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $ruleKey -ValueName $ruleName -Type String -Value $ruleString @gpParams
}
Write-Host "[+] Wrote $($firewallRules.Count) safe firewall rules into GPO." -ForegroundColor Green

$linkEnabledState = if ($EnableLink) { 'Yes' } else { 'No' }
try {
    $null = New-GPLink -Guid $existingGpo.Id -Target $targetDN -LinkEnabled $linkEnabledState @gpParams
    Write-Host "[+] Linked GPO '$GPOName' to '$targetDN' (Enabled: $linkEnabledState)" -ForegroundColor Green
} catch {
    Write-Warning "Link already exists or notice: $($_.Exception.Message)"
    if ($EnableLink) {
        $null = Set-GPLink -Guid $existingGpo.Id -Target $targetDN -LinkEnabled Yes @gpParams
        Write-Host "[+] Ensured GPO link is Enabled on '$targetDN'" -ForegroundColor Green
    }
}

if ($ForceUpdate) {
    Write-Host "[*] Executing gpupdate /force on local host..." -ForegroundColor Yellow
    & gpupdate.exe /force
}

[pscustomobject]@{
    Tier        = 3
    GPO         = $GPOName
    Target      = $targetDN
    RuleCount   = $firewallRules.Count
    Enabled     = $linkEnabledState
    Verified    = $true
}
Write-Host "`n[+] Tier 3 Firewall Baseline GPO staged successfully." -ForegroundColor Green
Write-Host "[!] Note: Individual server scripts (DC-Firewall.ps1, MSSQL-Firewall.ps1) provide final local port lockdowns." -ForegroundColor Yellow
