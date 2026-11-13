#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$TargetOU,
    [ValidateNotNullOrEmpty()][string]$GPOName = 'CCDC-LogonBanner',

    [ValidateNotNullOrEmpty()]
    [string]$Title = 'Authorized Use Only',

    [ValidateNotNullOrEmpty()]
    [string]$Message = 'This system is for authorized users only. Unauthorized access or use is prohibited and may result in prosecution. All activity may be monitored and recorded.',

    [string]$MessagePath,

    [switch]$EnableLink,

    [switch]$ForceUpdate
)

$ErrorActionPreference = 'Stop'

if ($MessagePath) {
    if (!(Test-Path -LiteralPath $MessagePath -PathType Leaf)) {
        throw "MessagePath file not found: $MessagePath"
    }
    $Message = Get-Content -LiteralPath $MessagePath -Raw -Encoding UTF8
}

if ([string]::IsNullOrWhiteSpace($Title) -or [string]::IsNullOrWhiteSpace($Message)) {
    throw 'The banner title and message must contain text.'
}

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
$policyKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         TIER 2: CCDC DOMAIN-WIDE LOGON BANNER GPO        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Domain      : $($domain.DNSRoot) | PDC: $server"
Write-Host "Target OU/DN: $targetDN"
Write-Host "GPO Name    : $GPOName"
Write-Host "Enable Link : $EnableLink"
Write-Host "Banner Title: $Title"
Write-Host "Banner Text : `n$Message" -ForegroundColor Gray
Write-Host "----------------------------------------------------------"

if (!$PSCmdlet.ShouldProcess($GPOName, "Deploy interactive logon banner to '$targetDN'")) { return }

$existingGpo = Get-GPO -Name $GPOName @gpParams -ErrorAction SilentlyContinue

if (!$existingGpo) {
    $existingGpo = New-GPO -Name $GPOName -Comment "CCDC Tier 2 Logon Banner Policy - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" @gpParams
    Write-Host "[+] Created GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
} else {
    Write-Host "[+] Found existing GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
}

$null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticecaption' -Type String -Value $Title @gpParams
$null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticetext' -Type String -Value $Message @gpParams

$captionCheck = Get-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticecaption' @gpParams
$textCheck = Get-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticetext' @gpParams

if ($captionCheck.Value -cne $Title -or $textCheck.Value -cne $Message) {
    throw "GPO verification failed for '$GPOName'. Readback values do not match."
}
Write-Host "[+] Verified GPO registry values for legalnoticecaption and legalnoticetext." -ForegroundColor Green

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
    Tier        = 2
    GPO         = $GPOName
    Target      = $targetDN
    Enabled     = $linkEnabledState
    Verified    = $true
}
Write-Host "`n[+] Tier 2 Logon Banner GPO deployed successfully." -ForegroundColor Green
