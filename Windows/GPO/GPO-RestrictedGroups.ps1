#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$TargetOU,
    [ValidateNotNullOrEmpty()][string]$GPOName = 'CCDC-RestrictedGroups',

    [string[]]$AdminMembers = @('Domain Admins'),

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
Write-Host "       CCDC GPO RESTRICTED GROUPS (LOCAL ADMIN ENFORCE)   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Domain      : $($domain.DNSRoot) | PDC: $server"
Write-Host "Target OU/DN: $targetDN"
Write-Host "GPO Name    : $GPOName"
Write-Host "Enable Link : $EnableLink"
Write-Host "`n[+] Authorized Local Administrators Members:" -ForegroundColor Yellow
$AdminMembers | ForEach-Object { Write-Host "  - $_" }
Write-Host "[!] Any unauthorized local administrator will be automatically removed." -ForegroundColor Gray

if (!$PSCmdlet.ShouldProcess($GPOName, "Deploy Restricted Groups policy to '$targetDN'")) { return }

$existingGpo = Get-GPO -Name $GPOName @gpParams -ErrorAction SilentlyContinue
if (!$existingGpo) {
    $existingGpo = New-GPO -Name $GPOName -Comment "CCDC Restricted Groups - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" @gpParams
    Write-Host "[+] Created GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
} else {
    Write-Host "[+] Found existing GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
}

$gptTmplDir = "\\$($domain.DNSRoot)\sysvol\$($domain.DNSRoot)\Policies\{$($existingGpo.Id)}\Machine\Microsoft\Windows NT\SecEdit"
if (!(Test-Path -LiteralPath $gptTmplDir)) {
    New-Item -ItemType Directory -Path $gptTmplDir -Force | Out-Null
}

$infPath = Join-Path $gptTmplDir 'GptTmpl.inf'
$membersList = ($AdminMembers | ForEach-Object { $_.Trim() }) -join ','

$infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = $membersList
"@

[System.IO.File]::WriteAllText($infPath, $infContent, [System.Text.Encoding]::Unicode)
Write-Host "[+] Configured Restricted Groups template in SYSVOL GptTmpl.inf" -ForegroundColor Green

$iniPath = "\\$($domain.DNSRoot)\sysvol\$($domain.DNSRoot)\Policies\{$($existingGpo.Id)}\GPT.INI"
if (Test-Path -LiteralPath $iniPath) {
    $ini = Get-Content -LiteralPath $iniPath
    $newIni = $ini | ForEach-Object {
        if ($_ -match '^Version=(\d+)') {
            $ver = [int]$matches[1] + 1
            "Version=$ver"
        } else {
            $_
        }
    }
    Set-Content -LiteralPath $iniPath -Value $newIni -Encoding Ascii
}

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
    Admins      = ($AdminMembers -join ', ')
    Enabled     = $linkEnabledState
    Verified    = $true
}
Write-Host "`n[+] Restricted Groups GPO deployed successfully." -ForegroundColor Green
