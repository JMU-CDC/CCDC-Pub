#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Sets the Windows interactive logon notice locally or pushes it via Domain Group Policy (GPO).
.DESCRIPTION
Run in elevated Windows PowerShell with no arguments to apply the default warning locally.
To push domain-wide or to a target OU, specify -GPO (e.g. 'Default Domain Policy' or a new GPO name).
Override the title and text when an inject requires specific wording.
MessagePath reads a UTF-8 text file, preserving multiple paragraphs.
.EXAMPLE
.\Set-LogonBanner.ps1
.EXAMPLE
.\Set-LogonBanner.ps1 -GPO 'Default Domain Policy'
.EXAMPLE
.\Set-LogonBanner.ps1 -GPO 'CCDC-LogonBanner' -CreateGPO -TargetOU 'OU=Domain Controllers,DC=example,DC=local' -EnableLink
.EXAMPLE
.\Set-LogonBanner.ps1 -Title 'Authorized Use Only' -MessagePath .\banner.txt -GPO 'Default Domain Policy'
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Title = 'Authorized Use Only',

    [ValidateNotNullOrEmpty()]
    [string]$Message = 'This system is for authorized users only. Unauthorized access or use is prohibited and may result in prosecution. All activity may be monitored and recorded.',

    [ValidateNotNullOrEmpty()]
    [string]$MessagePath,

    # GPO parameters
    [string]$GPO,

    [switch]$CreateGPO,

    [string]$TargetOU,

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

$policyKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$regKeyLocal = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   CCDC WINDOWS LOGON BANNER CONFIGURATION   " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Banner title   : $Title"
Write-Host "Banner message : `n$Message" -ForegroundColor Gray
Write-Host "---------------------------------------------"

# --- GPO MODE ---
if ($GPO) {
    Write-Host "[*] Target mode: Domain Group Policy (GPO: '$GPO')" -ForegroundColor Yellow
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop

    $domain = Get-ADDomain
    $pdc = $domain.PDCEmulator
    $gpParams = @{ Domain = $domain.DNSRoot; Server = $pdc }

    $existingGpo = Get-GPO -Name $GPO @gpParams -ErrorAction SilentlyContinue

    if (!$existingGpo) {
        if (!$CreateGPO) {
            throw "GPO '$GPO' was not found in domain '$($domain.DNSRoot)'. Pass -CreateGPO to create it automatically."
        }
        if ($PSCmdlet.ShouldProcess($GPO, "Create new Group Policy Object in domain $($domain.DNSRoot)")) {
            $existingGpo = New-GPO -Name $GPO -Comment "CCDC Logon Banner Policy - Configured $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" @gpParams
            Write-Host "[+] Created GPO: $GPO (Id: $($existingGpo.Id))" -ForegroundColor Green
        } else {
            return
        }
    } else {
        Write-Host "[+] Found existing GPO: $GPO (Id: $($existingGpo.Id))" -ForegroundColor Green
    }

    if ($PSCmdlet.ShouldProcess($GPO, 'Set legalnoticecaption and legalnoticetext registry values in GPO')) {
        # Set caption
        $null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticecaption' -Type String -Value $Title @gpParams
        # Set text
        $null = Set-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticetext' -Type String -Value $Message @gpParams

        # Verify readback
        $captionCheck = Get-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticecaption' @gpParams
        $textCheck = Get-GPRegistryValue -Guid $existingGpo.Id -Key $policyKey -ValueName 'legalnoticetext' @gpParams

        if ($captionCheck.Value -cne $Title -or $textCheck.Value -cne $Message) {
            throw "GPO verification failed for '$GPO'. Readback values do not match."
        }
        Write-Host "[+] Verified GPO registry values for legalnoticecaption and legalnoticetext." -ForegroundColor Green
    }

    # Optional Link
    if ($TargetOU) {
        $linkTarget = $TargetOU
        if ($PSCmdlet.ShouldProcess($linkTarget, "Link GPO '$GPO' to $linkTarget")) {
            $linkEnabledState = if ($EnableLink) { 'Yes' } else { 'No' }
            try {
                $null = New-GPLink -Guid $existingGpo.Id -Target $linkTarget -LinkEnabled $linkEnabledState @gpParams
                Write-Host "[+] Linked GPO '$GPO' to '$linkTarget' (Enabled: $linkEnabledState)" -ForegroundColor Green
            } catch {
                Write-Warning "New-GPLink failed (link may already exist): $($_.Exception.Message)"
                if ($EnableLink) {
                    $null = Set-GPLink -Guid $existingGpo.Id -Target $linkTarget -LinkEnabled Yes @gpParams
                    Write-Host "[+] Ensured GPO link is Enabled on '$linkTarget'" -ForegroundColor Green
                }
            }
        }
    }

    if ($ForceUpdate) {
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run gpupdate /force')) {
            Write-Host "[*] Executing gpupdate /force on local host..." -ForegroundColor Yellow
            & gpupdate.exe /force
        }
    }

    [pscustomobject]@{
        Mode        = 'GPO'
        GPOName     = $GPO
        GPOId       = $existingGpo.Id
        Domain      = $domain.DNSRoot
        Title       = $Title
        TargetOU    = $TargetOU
        Verified    = $true
    }
    Write-Host "`n[+] GPO update complete. Check gpresult /r or fresh interactive sign-in on target hosts." -ForegroundColor Green
}
# --- LOCAL REGISTRY MODE ---
else {
    Write-Host "[*] Target mode: Local Computer Registry ($env:COMPUTERNAME)" -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set interactive logon banner title and message locally')) {
        New-Item -Path $regKeyLocal -Force | Out-Null
        New-ItemProperty -Path $regKeyLocal -Name legalnoticecaption -Value $Title -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regKeyLocal -Name legalnoticetext -Value $Message -PropertyType String -Force | Out-Null

        $actual = Get-ItemProperty -LiteralPath $regKeyLocal
        if ($actual.legalnoticecaption -cne $Title -or $actual.legalnoticetext -cne $Message) {
            throw 'Logon banner verification failed. Check permissions and applied Group Policy.'
        }

        if ($ForceUpdate) {
            Write-Host "[*] Executing gpupdate /force..." -ForegroundColor Yellow
            & gpupdate.exe /force
        }

        [pscustomobject]@{
            Mode             = 'Local'
            ComputerName     = $env:COMPUTERNAME
            Title            = $actual.legalnoticecaption
            Message          = $actual.legalnoticetext
            RegistryVerified = $true
        }
        Write-Host "`n[+] Saved and verified locally. Check a fresh interactive sign-in; keep your current admin session open." -ForegroundColor Green
    }
}
