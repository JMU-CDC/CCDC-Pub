#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install or update Sysmon using a staged Microsoft executable and the adjacent CCDC XML.
.DESCRIPTION
Run in elevated Windows PowerShell. No downloads, uninstall, reboot, or log clearing.
Enter applies setup; n skips. -WhatIf performs file/signature/service reads only.
Existing logs and configuration display are backed up before update. Supply
-PreviousConfigPath to also preserve the original restorable XML if available.
Custom service names require -ServiceName. Read README.md before deployment.
.EXAMPLE
.\Setup-Sysmon.ps1 -SysmonPath 'C:\Tools\optisys\x64\Sysmon64.exe' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$SysmonPath,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'sysmonconfig.xml'),
    [string]$PreviousConfigPath,
    [string]$ServiceName,
    [ValidateRange(64,4096)][int]$LogSizeMB = 256,
    [string]$BackupRoot = "$env:ProgramData\CCDC\SysmonSetup"
)
$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'

function Read-SetupChoice {
    param([string]$Name)
    Write-Host "`nNEXT: $Name" -ForegroundColor Cyan
    while ($true) {
        $answer = Read-Host 'Press Enter to run, or type n and press Enter to skip'
        if ($null -eq $answer) { throw 'Interactive input unavailable; use a console.' }
        if ($answer -eq '') { return $true }
        if ($answer.Trim() -ieq 'n') { return $false }
        Write-Host 'Only an empty Enter runs the action. Type n to skip.'
    }
}

function Test-SysmonExecutable {
    param([string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $version = (Get-Item -LiteralPath $Path).VersionInfo
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') {
        throw 'Sysmon must have a valid Microsoft Corporation signature. Obtain a trusted copy; do not bypass signature checks.'
    }
    if ($version.OriginalFilename -notmatch '^Sysmon(64|64a)?\.exe$' -or $version.FileMajorPart -lt 13) {
        throw 'Expected a Sysmon executable version 13 or newer. Use the correct architecture for this host.'
    }
}

function Invoke-SetupNative {
    param([string]$File, [string[]]$Arguments)
    # Windows PowerShell can turn a successful native tool's stderr banner into
    # a terminating error under Stop. Decide native success by its exit code.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $File @Arguments 2>&1
        $nativeExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($nativeExitCode -ne 0) { throw "$File failed with exit code $nativeExitCode. $($output | Out-String)" }
    return ($output | Out-String)
}

function Set-SysmonConfiguration {
    param([string]$Executable, [string]$XmlPath, [bool]$AlreadyInstalled)
    # Updating an existing installation does not uninstall its service or driver.
    $arguments = if ($AlreadyInstalled) { @('-accepteula','-c',$XmlPath) } else { @('-accepteula','-i',$XmlPath) }
    Invoke-SetupNative -File $Executable -Arguments $arguments | Out-Host
}

# Read-only validation happens even for -WhatIf; never execute the tool in preview.
$SysmonPath = (Resolve-Path -LiteralPath $SysmonPath).ProviderPath
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
Test-SysmonExecutable -Path $SysmonPath
$xml = New-Object System.Xml.XmlDocument
$xml.XmlResolver = $null
$xml.Load($ConfigPath)
if ($xml.DocumentElement.Name -ne 'Sysmon' -or !$xml.SelectSingleNode('/Sysmon/EventFiltering')) {
    throw 'ConfigPath must be a Sysmon XML configuration with EventFiltering.'
}
$configHash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
$binaryHash = (Get-FileHash -LiteralPath $SysmonPath -Algorithm SHA256).Hash
if ($PreviousConfigPath) { $PreviousConfigPath = (Resolve-Path -LiteralPath $PreviousConfigPath).ProviderPath }
$services = @(Get-CimInstance Win32_Service | Where-Object {
    $_.Name -in @('Sysmon','Sysmon64','Sysmon64a') -or $_.DisplayName -like '*Sysmon*' -or ($ServiceName -and $_.Name -eq $ServiceName)
})
if ($services.Count -gt 1) { throw 'Multiple Sysmon service candidates found. Review the installation before proceeding.' }
if ($ServiceName -and ($services.Count -ne 1 -or $services[0].Name -ne $ServiceName)) {
    throw 'The specified existing ServiceName was not uniquely found.'
}
$alreadyInstalled = $services.Count -eq 1
$operation = if ($alreadyInstalled) { "Update existing Sysmon service $($services[0].Name)" } else { 'Install Sysmon service and driver' }
Write-Host "$operation using $SysmonPath" -ForegroundColor Cyan
Write-Host "Configuration: $ConfigPath (SHA256 $configHash)"
Write-Host 'Setup accepts the Sysinternals EULA. Broad logging may increase CPU, disk, and event volume.'
Write-Host 'If Sysmon was installed with a custom name, supply -ServiceName; automatic detection is limited.'
if (!$PSCmdlet.ShouldProcess($operation, 'Back up evidence, stage files, accept EULA, and apply configuration')) { return }
if (!(Read-SetupChoice $operation)) { Write-Host '[Skipped] Sysmon setup.'; return }

# One unique protected directory per accepted run; failed backups stop setup.
$backup = Join-Path $BackupRoot ("$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([guid]::NewGuid())")
New-Item -ItemType Directory -Path $backup | Out-Null
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
Set-Acl -LiteralPath $backup -AclObject $acl
$stagedExe = Join-Path $backup ([IO.Path]::GetFileName($SysmonPath))
$stagedXml = Join-Path $backup 'AppliedConfig.xml'
Copy-Item -LiteralPath $SysmonPath -Destination $stagedExe
Copy-Item -LiteralPath $ConfigPath -Destination $stagedXml
if ((Get-FileHash -LiteralPath $stagedExe -Algorithm SHA256).Hash -ne $binaryHash -or
    (Get-FileHash -LiteralPath $stagedXml -Algorithm SHA256).Hash -ne $configHash) {
    throw 'Staged files changed since validation; setup stopped.'
}
Test-SysmonExecutable -Path $stagedExe
if ($PreviousConfigPath) { Copy-Item -LiteralPath $PreviousConfigPath -Destination (Join-Path $backup 'PreviousConfig.xml') }
if ($alreadyInstalled) {
    Invoke-SetupNative -File $stagedExe -Arguments @('-accepteula','-c') |
        Set-Content -LiteralPath (Join-Path $backup 'Configuration-Before.txt') -Encoding UTF8
    $services | Export-Clixml -LiteralPath (Join-Path $backup 'Services-Before.xml')
    $beforeLog = Get-WinEvent -ListLog $channel
    $beforeLog | Export-Clixml -LiteralPath (Join-Path $backup 'Channel-Before.xml')
    Invoke-SetupNative -File "$env:SystemRoot\System32\wevtutil.exe" -Arguments @('epl',$channel,(Join-Path $backup 'Sysmon-Before.evtx')) | Out-Null
    if (!$PreviousConfigPath) { Write-Warning 'Original XML was not supplied. Configuration-Before.txt is evidence, not a restorable XML backup.' }
}
Set-SysmonConfiguration -Executable $stagedExe -XmlPath $stagedXml -AlreadyInstalled $alreadyInstalled

# Fail clearly when the tool returns successfully but the expected config is not active.
$loaded = Invoke-SetupNative -File $stagedExe -Arguments @('-accepteula','-c')
$loaded | Set-Content -LiteralPath (Join-Path $backup 'Configuration-After.txt') -Encoding UTF8
if ($loaded.IndexOf($configHash, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "Could not verify the loaded configuration hash. Review output in $backup; setup may be partially applied."
}
$running = @(Get-CimInstance Win32_Service | Where-Object {
    $_.Name -in @('Sysmon','Sysmon64','Sysmon64a') -or $_.DisplayName -like '*Sysmon*' -or ($ServiceName -and $_.Name -eq $ServiceName)
})
if ($running.Count -ne 1 -or $running[0].State -ne 'Running') { throw 'Expected one running Sysmon service after setup.' }
$log = Get-WinEvent -ListLog $channel
if (!$log.IsEnabled) { throw 'Sysmon event channel is disabled; review event-channel policy.' }

$requestedBytes = [long]$LogSizeMB * 1MB
if ($log.MaximumSizeInBytes -lt $requestedBytes) {
    if ($PSCmdlet.ShouldProcess($channel, "Increase maximum event-log size to $LogSizeMB MiB") -and
        (Read-SetupChoice "Increase Sysmon event-log maximum to $LogSizeMB MiB (check disk space first)")) {
        Invoke-SetupNative -File "$env:SystemRoot\System32\wevtutil.exe" -Arguments @('sl',$channel,"/ms:$requestedBytes") | Out-Null
        if ((Get-WinEvent -ListLog $channel).MaximumSizeInBytes -lt $requestedBytes) { throw 'Event-log size readback failed.' }
    }
} else { Write-Host 'Existing event-log maximum meets/exceeds the requested size; preserved.' }
Write-Host "[Completed] Sysmon service is running; loaded config hash and event channel verified. Backups: $backup" -ForegroundColor Green
Write-Host 'Verify actual process/network/DNS/pipe events with harmless lab activity. Native role logging is separate; see README.md.'
