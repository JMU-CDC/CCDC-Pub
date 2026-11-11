#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$TargetOU,
    [ValidateNotNullOrEmpty()][string]$GPOName = ('CCDC Hardening {0} {1}' -f (Get-Date -Format yyyyMMdd-HHmmss), [guid]::NewGuid().ToString('N').Substring(0,8)),
    [switch]$EnableLink,

    # Domain Password & Lockout policy attributes
    [switch]$ConfigureDomainPasswordPolicy,
    [ValidateRange(1,14)][int]$MinPasswordLength = 12,
    [ValidateRange(0,24)][int]$PasswordHistoryCount = 24,
    [ValidateRange(0,999)][int]$LockoutThreshold = 0,
    [ValidateRange(1,99999)][int]$LockoutMinutes = 30,

    # Logon Banner options
    [switch]$IncludeLogonBanner,
    [string]$BannerTitle = 'Authorized Use Only',
    [string]$BannerMessage = 'This system is for authorized users only. Unauthorized access or use is prohibited and may result in prosecution. All activity may be monitored and recorded.',
    [string]$BannerMessagePath,

    [ValidateNotNullOrEmpty()][string]$BackupRoot = "$env:ProgramData\CCDC\GPOBackups"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($parameterName in 'MinPasswordLength','PasswordHistoryCount','LockoutMinutes') {
    if ($PSBoundParameters.ContainsKey($parameterName) -and !$ConfigureDomainPasswordPolicy) {
        throw "-$parameterName requires -ConfigureDomainPasswordPolicy."
    }
}

if ($GPOName.Trim() -in @('Default Domain Policy','Default Domain Controllers Policy')) {
    throw 'Choose a new GPO name; default policies are not modified directly.'
}

if ($BannerMessagePath) {
    if (!(Test-Path -LiteralPath $BannerMessagePath -PathType Leaf)) {
        throw "BannerMessagePath file not found: $BannerMessagePath"
    }
    $BannerMessage = Get-Content -LiteralPath $BannerMessagePath -Raw -Encoding UTF8
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$domain = Get-ADDomain
$server = $domain.PDCEmulator
$domain = Get-ADDomain -Server $server

# Support domain root (DC=domain,DC=local) as TargetOU
$ou = $null
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

$gp = @{ Domain = $domain.DNSRoot; Server = $server }
$existingGpos = @(Get-GPO -All @gp)
if (@($existingGpos | Where-Object { $_.DisplayName -eq $GPOName }).Count) {
    throw "GPO '$GPOName' already exists. Review it in GPMC or choose a new name."
}
$links = Get-GPInheritance -Target $targetDN @gp
$passwordBefore = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -Server $server

# ==============================================================================
# COMPREHENSIVE HARDENING & AUDITING REGISTRY VALUES
# ==============================================================================
# Packet pp.14-15: preserve authenticated AD WinRM and MSSQL SMB/RDP/SQL.
# Packet pp.17,19: preserve names, addressing, public access, accounts, and ICMP.
$settings = [System.Collections.Generic.List[hashtable]]::new()

# 1. Credential Theft & LSASS Protections
# Disable WDigest plaintext caching (Anti-Mimikatz)
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name='UseLogonCredential'; Type='DWord'; Value=0 })
# Limit blank password use to console only
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LimitBlankPasswordUse'; Type='DWord'; Value=1 })
# Restrict anonymous / null session enumeration
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='RestrictNullSessAccess'; Type='DWord'; Value=1 })
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Type='DWord'; Value=1 })
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Type='DWord'; Value=1 })
# Require NTLMv2, refuse LM & NTLMv1
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Type='DWord'; Value=5 })

# 2. Network Poisoning & Protocol Hardening
# Turn off LLMNR (Anti-Responder / NTLM theft)
$settings.Add(@{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMulticast'; Type='DWord'; Value=0 })
# Require SMB Server Signing (Anti-Relay)
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='RequireSecuritySignature'; Type='DWord'; Value=1 })
# Require SMB Client Signing (Anti-Relay)
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Type='DWord'; Value=1 })

# 3. UAC & Admin Protection
# Run all administrators in Admin Approval Mode
$settings.Add(@{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Type='DWord'; Value=1 })
# Prompt for consent on secure desktop
$settings.Add(@{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Type='DWord'; Value=2 })

# 4. Deep Visibility & Auditing
# Enforce advanced audit subcategories over legacy categories
$settings.Add(@{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='SCENoApplyLegacyAuditPolicy'; Type='DWord'; Value=1 })
# Include command line in process creation (Event 4688)
$settings.Add(@{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Type='DWord'; Value=1 })
# PowerShell Script Block Logging (Event 4104)
$settings.Add(@{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Type='DWord'; Value=1 })
# PowerShell Module Logging (Event 4103)
$settings.Add(@{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name='EnableModuleLogging'; Type='DWord'; Value=1 })
$settings.Add(@{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name='*'; Type='String'; Value='*' })

# 5. Optional Interactive Logon Banner
if ($IncludeLogonBanner) {
    $settings.Add(@{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='legalnoticecaption'; Type='String'; Value=$BannerTitle })
    $settings.Add(@{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='legalnoticetext'; Type='String'; Value=$BannerMessage })
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         CCDC ACTIVE DIRECTORY GPO STAGING TOOL           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Domain      : $($domain.DNSRoot) | PDC: $server"
Write-Host "Target OU/DN: $targetDN"
Write-Host "Staged GPO  : $GPOName"
Write-Host "Enable Link : $EnableLink"
Write-Host "`n[+] Registry Settings to be configured in GPO:" -ForegroundColor Yellow
$settings | ForEach-Object { Write-Host "  [$($_.Type)] $($_.Key)\$($_.Name) = $($_.Value)" }

Write-Host "`n[*] Manual Reminders (in GPMC -> Advanced Audit Policy Configuration):" -ForegroundColor Gray
Write-Host "  - Enable 'Audit Process Creation: Success' under Detailed Tracking (enables Event 4688)."
Write-Host "  - Enable 'Audit Logon: Success & Failure' under Logon/Logoff."
Write-Host "  - Preserve WinRM listeners (scored), RDP, SMB, SQL, ICMP, and operator access."

if ($ConfigureDomainPasswordPolicy) {
    Write-Warning "Password policy affects the ENTIRE domain, independent of TargetOU. Length=$MinPasswordLength; history=$PasswordHistoryCount; complexity enabled; reversible encryption disabled."
    Write-Warning "Lockout threshold=$LockoutThreshold; duration/window=$LockoutMinutes minutes. (Coordinate with Quotient PCR scoring)."
}

# Gate check for -WhatIf / Confirmation
if (!$PSCmdlet.ShouldProcess($domain.DNSRoot, "Back up existing GPOs and stage '$GPOName' on '$targetDN'")) { return }

$backupPath = Join-Path $BackupRoot ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $backupPath -Force
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $backupPath -AclObject $acl
Write-Host "`n[+] Protected GPO backup root created: $backupPath" -ForegroundColor Cyan

$gpo = $null
$linkCreated = $false

try {
    # Backup existing environment state before writing changes
    $links | Export-Clixml -LiteralPath (Join-Path $backupPath 'TargetLinks.xml')
    $passwordBefore | Export-Clixml -LiteralPath (Join-Path $backupPath 'DomainPasswordPolicy.xml')
    $domain | Export-Clixml -LiteralPath (Join-Path $backupPath 'Domain.xml')
    Write-Host "[*] Backing up existing GPOs..." -ForegroundColor Yellow
    foreach ($existing in $existingGpos) {
        $backup = Backup-GPO -Guid $existing.Id -Path $backupPath @gp
        if (!$backup) { throw "No backup returned for '$($existing.DisplayName)'." }
    }

    # Create and populate the GPO
    Write-Host "[*] Creating new GPO '$GPOName'..." -ForegroundColor Yellow
    $gpo = New-GPO -Name $GPOName -Comment '2026 MWCCDC: Staged comprehensive hardening; see Set-ADGPO.md; preserve scored services.' @gp

    Write-Host "[*] Writing hardened registry values to GPO..." -ForegroundColor Yellow
    foreach ($setting in $settings) {
        $type = if ($setting.ContainsKey('Type')) { $setting.Type } else { 'DWord' }
        $null = Set-GPRegistryValue -Guid $gpo.Id -Key $setting.Key -ValueName $setting.Name -Type $type -Value $setting.Value @gp
        $actual = Get-GPRegistryValue -Guid $gpo.Id -Key $setting.Key -ValueName $setting.Name @gp
        if ($actual.Type -ne $type -or $actual.Value -ne $setting.Value) {
            throw "GPO verification failed for setting: $($setting.Name)."
        }
    }
    Write-Host "[+] All registry values written and verified in GPO." -ForegroundColor Green

    Get-GPOReport -Guid $gpo.Id -ReportType Html -Path (Join-Path $backupPath 'HardeningGpo.html') @gp
    $stagedBackup = Backup-GPO -Guid $gpo.Id -Path $backupPath @gp
    if (!$stagedBackup) { throw 'Staged GPO backup returned no result.' }

    # Link GPO to target OU/Domain
    $linkCreated = $true
    $null = New-GPLink -Guid $gpo.Id -Target $targetDN -LinkEnabled No -Enforced No @gp
    Write-Host "[+] Staged GPO link on '$targetDN' (Initially Disabled for safety)." -ForegroundColor Yellow

    # Optional Domain Password Policy configuration
    if ($ConfigureDomainPasswordPolicy -and $PSCmdlet.ShouldProcess($domain.DNSRoot, 'Change domain-wide password/optional lockout attributes')) {
        $policy = @{
            Identity=$domain.DistinguishedName; Server=$server
            MinPasswordLength=$MinPasswordLength; PasswordHistoryCount=$PasswordHistoryCount
            ComplexityEnabled=$true; ReversibleEncryptionEnabled=$false
        }
        if ($PSBoundParameters.ContainsKey('LockoutThreshold')) {
            $policy.LockoutThreshold = $LockoutThreshold
            $policy.LockoutDuration = [TimeSpan]::FromMinutes($LockoutMinutes)
            $policy.LockoutObservationWindow = [TimeSpan]::FromMinutes($LockoutMinutes)
        }
        Set-ADDefaultDomainPasswordPolicy @policy
        $after = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -Server $server
        foreach ($key in $policy.Keys | Where-Object { $_ -notin 'Identity','Server' }) {
            if ($after.$key -ne $policy[$key]) { throw "Password policy verification failed: $key." }
        }
        $after | Export-Clixml -LiteralPath (Join-Path $backupPath 'DomainPasswordPolicyAfter.xml')
        Write-Host "[+] Domain Default Password Policy updated successfully." -ForegroundColor Green
    }

    # Enable link if requested
    $expectedEnabled = $false
    if ($EnableLink -and $PSCmdlet.ShouldProcess($targetDN, "Enable '$GPOName' link on '$targetDN'")) {
        $null = Set-GPLink -Guid $gpo.Id -Target $targetDN -LinkEnabled Yes @gp
        $expectedEnabled = $true
    }

    $finalLinks = Get-GPInheritance -Target $targetDN @gp
    $finalLink = @($finalLinks.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id })
    if ($finalLink.Count -ne 1) { throw 'New GPO link could not be verified.' }
    if ($finalLink[0].Enabled -ne $expectedEnabled) { throw 'New GPO link enablement did not match the requested state.' }
    $finalLinks | Export-Clixml -LiteralPath (Join-Path $backupPath 'TargetLinksAfter.xml')

    Write-Host "`n[+] GPO Staging Complete: $($gpo.Id)" -ForegroundColor Green
    Write-Host "    Link Target  : $targetDN"
    Write-Host "    Link Enabled : $($finalLink[0].Enabled)"
    Write-Host "    Backup Artifacts: $backupPath" -ForegroundColor Cyan
    Write-Host "`nNext Step: Run 'gpupdate /force' on target machines and verify scored services (ad-winrm, mssql-smb, mssql-rdp, ad-dns)." -ForegroundColor Yellow
}
catch {
    Write-Warning "Run failed: $($_.Exception.Message). Recovery artifacts: $backupPath"
    if ($linkCreated) {
        try {
            $null = Set-GPLink -Guid $gpo.Id -Target $targetDN -LinkEnabled No @gp
            Write-Warning 'Disabled the new link. Already-applied settings and domain password attributes require separate recovery.'
        }
        catch { Write-Warning "Could not disable new link: $($_.Exception.Message). Disable it in GPMC immediately." }
    }
    throw
}
