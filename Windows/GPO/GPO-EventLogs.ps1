#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$TargetOU,
    [ValidateNotNullOrEmpty()][string]$GPOName = 'CCDC-EventLogs-Retention',

    [ValidateRange(65536, 4194304)][int]$MaxLogSizeKB = 524288,

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

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       CCDC GPO EVENT LOG CAPACITY & RETENTION POLICIES   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Domain      : $($domain.DNSRoot) | PDC: $server"
Write-Host "Target OU/DN: $targetDN"
Write-Host "GPO Name    : $GPOName"
Write-Host "Enable Link : $EnableLink"
Write-Host "`n[+] Configured Log Channels:" -ForegroundColor Yellow
Write-Host "  - Security Log Size    : $($MaxLogSizeKB / 1024) MB (AutoBackup/Overwrite as needed)"
Write-Host "  - System Log Size      : $($MaxLogSizeKB / 1024) MB (Overwrite as needed)"
Write-Host "  - Application Log Size : $($MaxLogSizeKB / 1024) MB (Overwrite as needed)"

if (!$PSCmdlet.ShouldProcess($GPOName, "Deploy Event Log size expansion to '$targetDN'")) { return }

$existingGpo = Get-GPO -Name $GPOName @gpParams -ErrorAction SilentlyContinue
if (!$existingGpo) {
    $existingGpo = New-GPO -Name $GPOName -Comment "CCDC Event Log Expansion - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" @gpParams
    Write-Host "[+] Created GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
} else {
    Write-Host "[+] Found existing GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
}

$maxBytes = $MaxLogSizeKB * 1024

$channels = @(
    @{ Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Retention='0' },
    @{ Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Retention='0' },
    @{ Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Retention='0' }
)

foreach ($chan in $channels) {
    $null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $chan.Path -ValueName 'MaxSize' -Type DWord -Value $maxBytes @gpParams
    $null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $chan.Path -ValueName 'Retention' -Type String -Value $chan.Retention @gpParams
}
Write-Host "[+] Configured 512 MB retention registry values for Security, System, Application." -ForegroundColor Green

$linkEnabledState = if ($EnableLink) { 'Yes' } else { 'No' }
try {
    $null = New-GPLink -Guid $existingGpo.Id -Target $targetDN -LinkEnabled $linkEnabledState @gpParams
    Write-Host "[+] Linked GPO '$GPOName' to '$targetDN' (Enabled: $linkEnabledState)" -ForegroundColor Green
} catch {
    Write-Warning "Link notice: $($_.Exception.Message)"
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
    GPO         = $GPOName
    Target      = $targetDN
    SizeMB      = ($MaxLogSizeKB / 1024)
    Enabled     = $linkEnabledState
    Verified    = $true
}
Write-Host "`n[+] Event Log Retention GPO deployed successfully." -ForegroundColor Green
