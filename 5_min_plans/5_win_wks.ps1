#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Guided', 'Audit', 'Apply')][string]$Mode = 'Guided',
    [ValidateRange(1, 65535)][int[]]$ScoredTcpPort = @(),
    [ValidateRange(1, 65535)][int[]]$ScoredUdpPort = @(),
    [string[]]$AllowedSource = @('Any'),
    [string[]]$ResetUser = @(),
    [string[]]$DisableUser = @(),
    [string]$RecoveryAdminName,
    [string]$DefenderUpdateFile,
    [string]$ReportRoot = "$env:ProgramData\CCDC\Workstation"
)

$ErrorActionPreference = 'Stop'
$script:RunContext = $PSCmdlet
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:CanWriteReport = $false

function Read-StepChoice {
    param([string]$Name)
    Write-Host "`nNEXT: $Name" -ForegroundColor Cyan
    while ($true) {
        $answer = Read-Host 'Press Enter to run this action, or type n and press Enter to skip'
        if ($null -eq $answer) { throw 'Interactive input is unavailable; run from a console.' }
        if ($answer -eq '') { return $true }
        if ($answer.Trim() -ieq 'n') { return $false }
        Write-Host 'Only an empty Enter runs the action. Type n to skip.' -ForegroundColor Yellow
    }
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    $status = 'Skipped'
    $errorText = ''
    try {
        if (!$script:RunContext.ShouldProcess($Name, 'Run guided plan action')) {
            $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
        } elseif (Read-StepChoice $Name) {
            & $Action | Out-Host
            $status = 'Completed'
        }
    } catch [System.OperationCanceledException] {
        $errorText = $_.Exception.Message
    } catch {
        $status = 'Failed'
        $errorText = $_.Exception.Message
    }
    $script:Results.Add([pscustomobject]@{ Step=$Name; Status=$status; Error=$errorText })
    if ($status -eq 'Failed') { Write-Warning "$Name FAILED: $errorText. Review this before running the next action." }
    else { Write-Host "[$status] $Name" }
    return ($status -eq 'Completed')
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Test-SecureStringEqual {
    param([securestring]$First, [securestring]$Second)
    if ($First.Length -ne $Second.Length) { return $false }
    $firstPtr = [IntPtr]::Zero
    $secondPtr = [IntPtr]::Zero
    try {
        $firstPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $secondPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        for ($i = 0; $i -lt $First.Length; $i++) {
            if ([Runtime.InteropServices.Marshal]::ReadInt16($firstPtr, $i * 2) -ne
                [Runtime.InteropServices.Marshal]::ReadInt16($secondPtr, $i * 2)) { return $false }
        }
        return $true
    } finally {
        if ($firstPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($firstPtr) }
        if ($secondPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPtr) }
    }
}

function Read-NewPassword {
    param([string]$Account)
    while ($true) {
        $first = Read-Host "New password for $Account" -AsSecureString
        $second = Read-Host "Confirm new password for $Account" -AsSecureString
        if ($null -eq $first -or $null -eq $second) { throw 'Secure password input is unavailable.' }
        $secondMatches = Test-SecureStringEqual $first $second
        $second.Dispose()
        if ($first.Length -gt 0 -and $secondMatches) { return $first }
        $first.Dispose()
        Write-Host 'Passwords must be nonempty and match. Try again.' -ForegroundColor Yellow
    }
}

function Get-SelectedUser {
    param([string]$Identity)
    $user = Get-LocalUser -Name $Identity
    if ($user.SID.Value -match '-(501|503|504)$') {
        throw "Reserved account $Identity is excluded from selected-user operations."
    }
    return $user
}

function Get-GroupMemberText {
    param([string]$GroupSid)
    $g = (Get-LocalGroup -SID $GroupSid -ErrorAction SilentlyContinue).Name
    if ($g) { "== $g ($GroupSid)"; & net.exe localgroup $g }
}

function Set-RegistryDword {
    param([string]$Description, [string]$Path, [string]$Name, [int]$Value)
    Invoke-Step "$Description ($Name = $Value)" {
        if (!(Test-Path -Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        if ((Get-ItemProperty -Path $Path -Name $Name).$Name -ne $Value) { throw 'Registry readback did not match.' }
    } | Out-Null
}

function Set-AllowRule {
    param([string]$Name, [string]$Protocol, [string[]]$Port, [string[]]$Address)
    $ruleName = "CCDC-WS-$Name"
    return (Invoke-Step "Allow inbound $Protocol ports $($Port -join ',') from $($Address -join ',') [$ruleName]" {
        $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            $existing | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any
            $existing | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol $Protocol -LocalPort $Port
            $existing | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $Address
        } else {
            New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Group 'CCDC Workstation' `
                -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $Protocol `
                -LocalPort $Port -RemoteAddress $Address | Out-Null
        }
    })
}

function Export-Evidence {
    param([string]$Name, [scriptblock]$Query)
    Invoke-Step "Review/export $Name" {
        $data = & $Query
        $data | Out-Host
        if ($script:CanWriteReport) { $data | Export-Clixml -LiteralPath (Join-Path $report "$Name.xml") -Depth 6 }
    } | Out-Null
}

$computer = Get-CimInstance Win32_ComputerSystem
if ($computer.DomainRole -notin 0, 1) { throw 'This is the WORKSTATION plan. Use the server/AD script on servers and DCs.' }
Import-Module NetSecurity
$administrator = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
$report = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
Write-Host 'Guided workstation plan: Enter runs one action; n skips it; Ctrl+C stops.' -ForegroundColor Cyan
Write-Host 'Complete your manual backup/snapshot first. This script does not create one.'
Write-Host "Host: $env:COMPUTERNAME  Domain-joined: $($computer.PartOfDomain) ($($computer.Domain))  Local admin: $($administrator.Name)"
Write-Host 'NOTE: only LOCAL accounts/policy are changed. Domain accounts must be handled on the DC; domain GPO can overwrite local settings.' -ForegroundColor Yellow

Invoke-Step 'Set timestamped PowerShell and child CMD prompts for this session' {
    function global:prompt { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')] | PS $(Get-Location)`n--> " }
    $env:PROMPT = '$D$S$T$H$H$H$S$B$S$P$_--$G'
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')] Shell timestamps enabled."
} | Out-Null

$script:CanWriteReport = Invoke-Step "Create protected report directory: $report" {
    New-Item -ItemType Directory -Path $report -Force | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $report -AclObject $acl
}
Export-Evidence 'Services-Before' { Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, StartName, PathName }
if ($script:CanWriteReport) {
    Invoke-Step 'Export original firewall policy' { Invoke-Native netsh.exe @('advfirewall','export',(Join-Path $report 'firewall-before.wfw')) } | Out-Null
    Invoke-Step 'Export original audit policy' { Invoke-Native auditpol.exe @('/backup',"/file:$(Join-Path $report 'audit-before.csv')") } | Out-Null
}

if ($Mode -ne 'Audit') {
    Write-Host "`n1. Passwords and accounts (LOCAL)" -ForegroundColor Cyan

    Invoke-Step 'Create LOCAL backup administrator AND add it to local Administrators: next prompts ask for username and password' {
        $name = Read-Host 'Username for the NEW local backup administrator'
        if (!$name -and $RecoveryAdminName) { $name = $RecoveryAdminName }
        if ($name -notmatch '^[a-zA-Z0-9._-]{1,20}$') { throw 'Enter a simple username (1-20 letters, digits, dots, underscores or hyphens).' }
        if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { throw "Account $name already exists; nothing was changed." }
        $secret = Read-NewPassword $name
        try {
            $new = New-LocalUser -Name $name -Password $secret -PasswordNeverExpires -AccountNeverExpires -Description 'CCDC backup admin'
            Get-LocalGroup -SID 'S-1-5-32-544' | Add-LocalGroupMember -Member $new
            $groupName = (Get-LocalGroup -SID 'S-1-5-32-544').Name
            if (!((& net.exe localgroup $groupName) -match [regex]::Escape($name))) { throw 'Administrator membership verification failed.' }
        } finally { $secret.Dispose() }
    } | Out-Null

    Invoke-Step "Change local administrator password: $($administrator.Name) (coordinate scoring credentials)" {
        $secret = Read-NewPassword $administrator.Name
        try { Set-LocalUser -InputObject $administrator -Password $secret }
        finally { $secret.Dispose() }
    } | Out-Null

    foreach ($identity in $ResetUser) {
        Invoke-Step "Reset selected LOCAL user password: $identity (coordinate service/scoring credentials)" {
            $selected = Get-SelectedUser $identity
            $secret = Read-NewPassword $selected.Name
            try { Set-LocalUser -InputObject $selected -Password $secret }
            finally { $secret.Dispose() }
        } | Out-Null
    }

    Invoke-Step 'Disable the local Guest account' {
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
        Disable-LocalUser -InputObject $guest
        if ((Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Enabled) { throw 'Guest is still enabled.' }
    } | Out-Null

    Set-RegistryDword 'Restrict anonymous access' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1

    Invoke-Step 'Set LOCAL minimum password length to 12 characters' {
        Invoke-Native net.exe @('accounts','/minpwlen:12')
    } | Out-Null
    Invoke-Step 'Set LOCAL lockout to 5 failures / 30 minutes (can disrupt scoring and enable lockout attacks)' {
        Invoke-Native net.exe @('accounts','/lockoutthreshold:5','/lockoutduration:30','/lockoutwindow:30')
    } | Out-Null

    Export-Evidence 'Accounts-Before' { Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon,PasswordLastSet,Description }

    foreach ($identity in $DisableUser) {
        Invoke-Step "Disable selected suspicious LOCAL account: $identity" {
            $selected = Get-SelectedUser $identity
            if ($selected.SID.Value -match '-500$' -or $selected.SID.Value -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
                throw 'Refusing to disable the built-in Administrator or current operator.'
            }
            Disable-LocalUser -InputObject $selected
        } | Out-Null
    }
    Export-Evidence 'Sessions' { Invoke-Native query.exe @('session') }

    Write-Host "`n2. Features and services" -ForegroundColor Cyan
    Invoke-Step 'Remove the current operator screensaver executable setting' {
        if (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue) {
            Remove-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE
        }
    } | Out-Null
    Invoke-Step 'Manual Sticky Keys check: open Accessibility settings and disable unneeded keyboard shortcuts' {
        Write-Host 'Use Settings -> Accessibility -> Keyboard. Binary integrity is reviewed later; no system binaries are replaced.'
    } | Out-Null
    Invoke-Step 'Disable SMBv1 on the SMB server' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } | Out-Null
    Invoke-Step 'Disable SMBv1 optional feature (needs restart; skip if unavailable)' {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($f -and $f.State -eq 'Enabled') { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
    } | Out-Null
    Invoke-Step 'Require SMB SERVER signing' { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force } | Out-Null
    Invoke-Step 'Require SMB CLIENT signing (may break access to non-signing shares)' { Set-SmbClientConfiguration -RequireSecuritySignature $true -Force } | Out-Null
    Set-RegistryDword 'Disable LLMNR' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    foreach ($nic in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True') {
        Invoke-Step "Disable NetBIOS over TCP/IP on adapter: $($nic.Description)" {
            $outcome = Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2}
            if ($outcome.ReturnValue -notin 0,1) { throw "NetBIOS change failed: $($outcome.ReturnValue)" }
            if ($outcome.ReturnValue -eq 1) { Write-Warning 'NetBIOS change needs a restart.' }
        } | Out-Null
    }
    foreach ($tunnel in 'teredo','6to4','isatap') {
        Invoke-Step "Disable IPv6 $tunnel tunnel (native IPv6 stays enabled)" {
            $arguments = if ($tunnel -eq 'teredo') { @('interface','teredo','set','state','disabled') }
                else { @('interface','ipv6',$tunnel,'set','state','state=disabled') }
            Invoke-Native netsh.exe $arguments
        } | Out-Null
    }
    foreach ($serviceName in 'Spooler','WinRM','RemoteRegistry','SSDPSRV','upnphost') {
        Invoke-Step "Stop service $serviceName (skip WinRM if needed for management; skip Spooler if you must print)" {
            if (!(Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { Write-Host "$serviceName not present."; return }
            Stop-Service -Name $serviceName -Force
            if ((Get-Service $serviceName).Status -ne 'Stopped') { throw 'Service did not stop.' }
        } | Out-Null
        Invoke-Step "Disable service $serviceName startup" {
            if (!(Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { Write-Host "$serviceName not present."; return }
            Set-Service -Name $serviceName -StartupType Disabled
        } | Out-Null
    }
    Set-RegistryDword 'Disable Remote Assistance' 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0
    Set-RegistryDword 'Deny inbound RDP (SKIP if you or the scorer use RDP to this box)' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    Set-RegistryDword 'Disable AutoRun/AutoPlay on all drive types' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
    Set-RegistryDword 'Disable WDigest plaintext credential caching' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0

    Write-Host "`n3. Firewall and connections" -ForegroundColor Cyan
    Write-Host 'No AD/DC port rules are offered (not needed on a workstation). Add -ScoredTcpPort / -ScoredUdpPort for anything that must reach this box.' -ForegroundColor Yellow
    foreach ($port in $ScoredTcpPort) { Set-AllowRule "TCP-$port" TCP @("$port") $AllowedSource | Out-Null }
    foreach ($port in $ScoredUdpPort) { Set-AllowRule "UDP-$port" UDP @("$port") $AllowedSource | Out-Null }
    Invoke-Step 'Allow inbound ICMPv4 echo requests for reachability/scoring checks' {
        if (!(Get-NetFirewallRule -Name CCDC-WS-ICMP -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name CCDC-WS-ICMP -DisplayName CCDC-WS-ICMP -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
        }
    } | Out-Null
    Invoke-Step 'Enable Windows Firewall on all profiles' {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    } | Out-Null
    Invoke-Step 'Block unmatched inbound traffic and allow outbound traffic' {
        if ($env:SESSIONNAME -like 'RDP*' -and 3389 -notin $ScoredTcpPort) {
            throw 'You are in an RDP session and no 3389 allow rule was requested; refusing to lock yourself out. Re-run with -ScoredTcpPort 3389 (and skip the RDP deny step).'
        }
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow
    } | Out-Null
    Invoke-Step 'Enable firewall allowed/blocked traffic logging (32 MB per profile)' {
        Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 32767
    } | Out-Null
    Export-Evidence 'Connections' { Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess }

    Write-Host "`n4. Audit and logging" -ForegroundColor Cyan
    Set-RegistryDword 'Use advanced audit subcategories instead of legacy audit policy' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
    Invoke-Step 'Enable success/failure auditing for all categories' { Invoke-Native auditpol.exe @('/set','/category:*','/success:enable','/failure:enable') } | Out-Null
    Set-RegistryDword 'Enable PowerShell script block logging' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    Invoke-Step 'Enable PowerShell module logging for all modules' {
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        if (!(Test-Path "$key\ModuleNames")) { New-Item -Path "$key\ModuleNames" -Force | Out-Null }
        New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
    } | Out-Null
    Invoke-Step 'Enable PowerShell transcription to the protected report directory' {
        if (!$script:CanWriteReport) { throw 'Protected report directory was skipped or failed; transcription was not enabled.' }
        $transcripts = Join-Path $report 'Transcripts'
        New-Item -ItemType Directory -Path $transcripts -Force | Out-Null
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -Path $key -Name EnableTranscripting -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name OutputDirectory -Value $transcripts -PropertyType String -Force | Out-Null
    } | Out-Null
    Set-RegistryDword 'Include command lines in process creation events' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Set-RegistryDword 'Enable UAC (may require a later reboot)' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    Set-RegistryDword 'Require administrator consent on the secure desktop' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2

    if ($DefenderUpdateFile) {
        Invoke-Step "Install staged offline Defender signature update: $DefenderUpdateFile" {
            if (!(Test-Path -LiteralPath $DefenderUpdateFile)) { throw 'Defender update file not found.' }
            Invoke-Native $DefenderUpdateFile @()
        } | Out-Null
    } else {
        Write-Host 'No -DefenderUpdateFile supplied; skipping signature update (no network).' -ForegroundColor Yellow
    }
    Invoke-Step 'Make sure Defender real-time protection is on (fails harmlessly if Tamper Protection/other AV blocks it)' {
        Set-MpPreference -DisableRealtimeMonitoring $false
    } | Out-Null

    Write-Host "`n5. Credential hardening" -ForegroundColor Cyan
    Set-RegistryDword 'Require NTLMv2 and refuse LM/NTLMv1' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
}

Export-Evidence 'Accounts-After' { Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon,PasswordLastSet,Description }
Export-Evidence 'LocalPasswordPolicy' { Invoke-Native net.exe @('accounts') }
Export-Evidence 'Services-After' { Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName }
Export-Evidence 'ListeningPorts' { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort }
Export-Evidence 'UdpEndpoints' { Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort }
Export-Evidence 'Processes' { Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine }
Export-Evidence 'Tasks' { Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Actions,Principal,Triggers }
Export-Evidence 'StartupRegistry' {
    foreach ($path in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon')) {
        if (Test-Path $path) { Get-ItemProperty $path }
    }
}
Export-Evidence 'StartupFolders' {
    foreach ($dir in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup") {
        if (Test-Path $dir) { Get-ChildItem -LiteralPath $dir -Force | Select-Object FullName,Length,LastWriteTime }
    }
}
Export-Evidence 'WMI-Persistence' {
    foreach ($class in '__EventFilter','__EventConsumer','__FilterToConsumerBinding') { Get-CimInstance -Namespace root/subscription -ClassName $class }
}
Export-Evidence 'AccessibilityBinaries' {
    foreach ($name in 'sethc.exe','utilman.exe','narrator.exe','osk.exe','magnify.exe') {
        $file = Join-Path "$env:SystemRoot\System32" $name
        if (Test-Path -LiteralPath $file) {
            Get-FileHash -LiteralPath $file -Algorithm SHA256
            Get-AuthenticodeSignature -LiteralPath $file | Select-Object Path,Status,StatusMessage
        }
    }
}
Export-Evidence 'PrivilegedLocalGroups' {
    foreach ($sid in 'S-1-5-32-544','S-1-5-32-555','S-1-5-32-551','S-1-5-32-580') { Get-GroupMemberText $sid }
}
Export-Evidence 'SmbShares' { Get-SmbShare | Select-Object Name,Path,Description,CurrentUsers }
Export-Evidence 'HostsFile' { Get-Content -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" }
Export-Evidence 'RecentEvents' {
    foreach ($log in 'Security','System') {
        $ids = if ($log -eq 'Security') { @(4720,4625,4728,4732,4756,1102) } else { @(7045) }
        $eventErrors = @()
        $events = Get-WinEvent -FilterHashtable @{LogName=$log;Id=$ids;StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue -ErrorVariable eventErrors
        foreach ($err in $eventErrors) { if ($err.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw $err } }
        $events | Select-Object TimeCreated,Id,LogName,Message
    }
}
Export-Evidence 'DefenderStatus' { Get-MpComputerStatus }
Invoke-Step 'Review incident-response follow-up manually' {
    Write-Host 'Test scored services, console/remote access and scoring. Review evidence before killing processes or deleting tasks/services/registry entries. Record incidents. No automatic reboot. Restore network only after the review.'
} | Out-Null
if ($script:CanWriteReport) {
    Invoke-Step 'Export applied GPO report (gpresult, local)' {
        Invoke-Native gpresult.exe @('/h',(Join-Path $report 'GPO.html'),'/f')
    } | Out-Null
    Invoke-Step 'Save walkthrough results.csv in the protected report directory' {
        $script:Results | Export-Csv -LiteralPath (Join-Path $report 'results.csv') -NoTypeInformation
    } | Out-Null
    Write-Host "Report directory: $report"
}
$script:Results | Format-Table -AutoSize
if (@($script:Results | Where-Object Status -eq 'Failed').Count) { throw 'Some actions failed. Review the summary; the plan is not fully complete.' }
