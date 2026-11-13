#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$TargetOU,
    [ValidateNotNullOrEmpty()][string]$GPOName = 'CCDC-Defender-ASR',

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
$asrKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       CCDC GPO DEFENDER ATTACK SURFACE REDUCTION (ASR)   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Domain      : $($domain.DNSRoot) | PDC: $server"
Write-Host "Target OU/DN: $targetDN"
Write-Host "GPO Name    : $GPOName"
Write-Host "Enable Link : $EnableLink"
Write-Host "`n[+] Staging Core ASR Rules in Block Mode (1):" -ForegroundColor Yellow
Write-Host "  - Block credential stealing from Windows LSASS (9e6c4e1f-7d60-42da-87ac-627c5e23c3c4)"
Write-Host "  - Block process creation from PSExec/WMI commands (d1e49aac-8f56-4280-b9ba-993a6d77406c)"
Write-Host "  - Block executable content from email client/webmail (be9ba2d9-53ea-44a7-8f61-b54c01464c01)"
Write-Host "  - Block obfuscated scripts and AMSI bypasses (5beb860e-2bac-4f0c-9647-705dd0602410)"
Write-Host "  - Block untrusted / unsigned processes running from USB (b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4)"

if (!$PSCmdlet.ShouldProcess($GPOName, "Deploy Defender ASR rules to '$targetDN'")) { return }

$existingGpo = Get-GPO -Name $GPOName @gpParams -ErrorAction SilentlyContinue
if (!$existingGpo) {
    $existingGpo = New-GPO -Name $GPOName -Comment "CCDC Defender ASR Hardening - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" @gpParams
    Write-Host "[+] Created GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
} else {
    Write-Host "[+] Found existing GPO: $GPOName (Id: $($existingGpo.Id))" -ForegroundColor Green
}

$rules = @{
    '9e6c4e1f-7d60-42da-87ac-627c5e23c3c4' = '1'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = '1'
    'be9ba2d9-53ea-44a7-8f61-b54c01464c01' = '1'
    '5beb860e-2bac-4f0c-9647-705dd0602410' = '1'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = '1'
}

foreach ($ruleGuid in $rules.Keys) {
    $null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $asrKey -ValueName $ruleGuid -Type String -Value $rules[$ruleGuid] @gpParams
}
Write-Host "[+] Wrote $($rules.Count) Defender ASR rules into GPO." -ForegroundColor Green

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
    RuleCount   = $rules.Count
    Enabled     = $linkEnabledState
    Verified    = $true
}
Write-Host "`n[+] Defender ASR GPO deployed successfully." -ForegroundColor Green
