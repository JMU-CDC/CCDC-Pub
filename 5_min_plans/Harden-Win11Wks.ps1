<#
.SYNOPSIS
  Offline first-5-minutes hardening for the Windows 11 competition workstation that will also run the Velociraptor server.
.DESCRIPTION
  Windows 11 edition of Harden-Win10Wks.ps1 (same steps, see Win11-Scripts.SPEC.md for what differs). Windows PowerShell 5.1,
  no internet, installs nothing. No passwords in this file: it prompts, passes the value straight to Windows, never prints
  or stores it. Every registry, service and firewall change is recorded for -Undo.
  Extra for Velociraptor: the 'velo' step opens inbound TCP 8000 (client frontend) from any source. The GUI port 8889 is left
  closed because Velociraptor binds the GUI to 127.0.0.1 by default; -OpenGuiPort opens it too.
.PARAMETER Skip
  Steps to skip: accounts, fw, velo, proto, services, defender, audit (comma separated).
.PARAMETER DryRun
  Print the steps, change nothing.
.PARAMETER Undo
  Report folder of an earlier run. Reverts registry, services, firewall, Guest, Defender, audit policy, log sizes and the Velociraptor rules this run created.
.PARAMETER OutDir
  Report and undo folder, created if absent.
.PARAMETER VeloFrontendPort
  Velociraptor client (frontend) port, default 8000. Check it against the generated server.config.yaml.
.PARAMETER VeloGuiPort
  Velociraptor GUI port, default 8889.
.PARAMETER OpenGuiPort
  Also allow inbound TCP on the GUI port. Off by default: the GUI is localhost-only and exposing it gives the red team a login page.
.PARAMETER VeloFilePort
  Port the team serves client.config.yaml and the client installer on (python -m http.server 8080). Default 8080, 0 = no rule.
.PARAMETER KeepFileSharing
  Leave the File and Printer Sharing firewall group as found (only needed if an SMB share is hosted on this box).
#>
param(
    [string[]]$Skip = @(),
    [switch]$DryRun,
    [ValidateRange(12, 64)][int]$PwLength = 16,
    [ValidateRange(1, 65535)][int]$VeloFrontendPort = 8000,
    [ValidateRange(1, 65535)][int]$VeloGuiPort = 8889,
    [switch]$OpenGuiPort,
    [ValidateRange(0, 65535)][int]$VeloFilePort = 8080,
    [switch]$KeepFileSharing,
    [string]$Undo = '',
    [string]$OutDir = "C:\Reports\harden-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

# Windows 11 with Smart App Control or any application-control policy runs unsigned scripts in Constrained Language Mode,
# where New-Object on most .NET types and static calls fail partway through. Stop before changing anything.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw "PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode (Smart App Control or an application-control policy is on). This script needs FullLanguage. Do not run it; tell the team."
}

$ErrorActionPreference = 'Stop'
$Skip = @($Skip -split ',' | ForEach-Object { $_.Trim().ToLower() })   # -File passes "a,b" as one string
$known = 'accounts', 'fw', 'velo', 'proto', 'services', 'defender', 'audit'
$unk = @($Skip | Where-Object { $_ -and $known -notcontains $_ })
if ($unk) { throw "unknown -Skip value(s): $($unk -join ', '). Valid: $($known -join ', ')" }
$script:Reg  = New-Object System.Collections.ArrayList
$script:Svc  = New-Object System.Collections.ArrayList
$script:Fail = 0
$script:PwChanged   = New-Object System.Collections.ArrayList   # accounts whose password this run changed
$script:Misc = @{ VeloRules = @() }                      # state the registry/service/firewall undo does not cover; VeloRules = firewall rules this run created
# ASR rule IDs: LSASS credential theft, Office child processes, obfuscated scripts
$AsrIds = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
# Obfuscated-script rule is audit only: Velociraptor artifacts run powershell -EncodedCommand, and the rule leans on cloud protection this offline box lacks.
$AsrActs = 'Enabled', 'Enabled', 'AuditMode'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated (Administrator) PowerShell.'
}

# Nov 7: the 'Ubuntu workstation' was really Windows 7, which has none of these cmdlets. Stop early with a clear message.
$osv = [Environment]::OSVersion.Version
if ($osv.Major -lt 10) {
    throw "This is Windows $($osv.Major).$($osv.Minor). Get-LocalUser, Set-NetFirewallProfile and the Defender cmdlets do not exist here, so this script would fail partway. Do not run it; use the Windows 7/8 typed fallback in the plan (netsh advfirewall, net user, reg add)."
}

# ---------- undo ----------
if ($Undo) {
    $u = Import-Clixml (Join-Path $Undo 'undo.xml')
    foreach ($r in $u.Reg) {
        try {
            if ($null -eq $r.Old) { Remove-ItemProperty -Path $r.Path -Name $r.Name }
            else { Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Old -Type $r.Kind }
        } catch { Write-Warning "reg $($r.Path)\$($r.Name): $($_.Exception.Message)" }
    }
    foreach ($s in $u.Svc) {
        try { Set-Service $s.Name -StartupType $s.Old; if ($s.Running) { Start-Service $s.Name } }
        catch { Write-Warning "service $($s.Name): $($_.Exception.Message)" }
    }
    $wfw = Join-Path $Undo 'fw-before.wfw'
    if (Test-Path $wfw) {
        netsh advfirewall import $wfw | Out-Null
        if ($LASTEXITCODE) { Write-Warning 'firewall import failed' }
    } else { Write-Warning 'no fw-before.wfw in this folder (firewall step was skipped or its export failed): firewall not reverted' }
    $m = $u.Misc
    if ($m) {
        foreach ($n in @($m.VeloRules)) {
            if (-not $n) { continue }
            try { Remove-NetFirewallRule -DisplayName $n -ErrorAction Stop } catch { Write-Warning "firewall rule ${n}: $($_.Exception.Message)" }
        }
        try {
            if ($m.GuestWasEnabled) { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Enable-LocalUser }
        } catch { Write-Warning "Guest: $($_.Exception.Message)" }
        try {
            $af = Join-Path $Undo 'audit-before.csv'
            if (Test-Path $af) {
                auditpol /restore "/file:$af" | Out-Null   # quoted as one argument: a bare (Join-Path) would split into two
                if ($LASTEXITCODE) { Write-Warning 'audit policy restore failed' }
            } else { Write-Warning 'no audit-before.csv: audit policy not reverted' }
        } catch { Write-Warning "audit: $($_.Exception.Message)" }
        try {
            if ($m.Logs) {
                wevtutil sl Security "/ms:$($m.Logs.Security)"
                wevtutil sl Microsoft-Windows-PowerShell/Operational "/ms:$($m.Logs.PS)"
            } else { Write-Warning 'log sizes were not captured: not reverted' }
        } catch { Write-Warning "log sizes: $($_.Exception.Message)" }
        try {
            if ($null -ne $m.Smb1 -and $m.Smb1) { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force }
        } catch { Write-Warning "SMB1: $($_.Exception.Message)" }
        try {
            if (-not $m.Mp) { throw 'Defender settings were not captured, not reverted' }
            $d = $m.Mp
            Set-MpPreference -DisableRealtimeMonitoring $d.Rtm -DisableBehaviorMonitoring $d.Beh -PUAProtection $d.Pua
        } catch { Write-Warning "Defender (Tamper Protection can block this): $($_.Exception.Message)" }
        foreach ($id in $AsrIds) {
            try {
                if (-not $m.Mp) { break }
                $at = -1
                for ($i = 0; $i -lt @($m.Mp.AsrIds).Count; $i++) { if ("$(@($m.Mp.AsrIds)[$i])" -ieq $id) { $at = $i } }
                if ($at -ge 0) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions @($m.Mp.AsrActions)[$at] }
                else { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id }
            } catch { Write-Warning "ASR ${id}: $($_.Exception.Message)" }
        }
        if (@($m.PwAccounts).Count) {
            Write-Host "Passwords were changed for: $(@($m.PwAccounts) -join ', '). Original passwords are not stored and cannot be restored; set one with: net user <name> *" -ForegroundColor Yellow
        }
        Write-Host 'Undone: registry, services, firewall, Guest, Defender, audit policy, log sizes. Passwords are not restored.'
    } else {
        Write-Host 'Undone: registry, services, firewall. This folder predates full undo: Guest, Defender, audit and passwords are not reverted.'
    }
    return
}

# ---------- Windows 11 preflight (information only, nothing here stops the run) ----------
Write-Host "Build $($osv.Build)$(if ($osv.Build -ge 22000) { ' (Windows 11)' } else { ' is Windows 10; this is the Windows 11 copy of the script, every step still applies' })" -ForegroundColor Gray
try {
    # Value read is an inference from Microsoft's test page (0 off, 1 on, 2 evaluation); `citool.exe -lp` is the documented check.
    $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState
    switch ($sac) {
        0 { Write-Host 'Smart App Control: off' -ForegroundColor Gray }
        1 { Write-Host 'Smart App Control: ON (enforcing). An unsigned velociraptor.exe may be blocked; check Event Viewer > CodeIntegrity > Operational, event 3077.' -ForegroundColor Yellow }
        2 { Write-Host 'Smart App Control: evaluation mode (logs only, event 3076)' -ForegroundColor Gray }
        default { Write-Host "Smart App Control: unknown value $sac" -ForegroundColor Gray }
    }
} catch { Write-Host 'Smart App Control: state value not present (treat as off or unmanaged; `citool.exe -lp` shows policies)' -ForegroundColor Gray }

# ---------- helpers ----------
function Step($name, $desc, [scriptblock]$body) {
    if ($Skip -contains $name) { Write-Host "== [skip] $desc"; return }
    Write-Host "== $desc" -ForegroundColor Cyan
    if ($DryRun) { return }
    try { & $body } catch { Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red; $script:Fail++ }
}

# Run one item; a failure is reported and the rest of the step continues.
function T([scriptblock]$b) {
    try { & $b } catch { Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red; $script:Fail++ }
}

# Readback check: the evidence line for an inject screenshot.
function Ck($name, [scriptblock]$b) {
    $ok = $false
    try { $ok = [bool](& $b) } catch { }
    if ($ok) { Write-Host "  [PASS] $name" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $name" -ForegroundColor Red; $script:Fail++ }
}

# DWord set that remembers the old value (or its absence) for -Undo.
function Set-Reg($path, $name, $val) {
    try {
        $old = $null; $kind = $null
        if (Test-Path $path) {
            $k = Get-Item $path
            if ($k.GetValueNames() -contains $name) {
                $old = $k.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
                $kind = "$($k.GetValueKind($name))"
            }
        } else { New-Item $path -Force | Out-Null }
        [void]$script:Reg.Add([pscustomobject]@{ Path = $path; Name = $name; Old = $old; Kind = $kind })
        Set-ItemProperty -Path $path -Name $name -Value $val -Type DWord
    } catch { Write-Host "  [FAIL] reg $name : $($_.Exception.Message)" -ForegroundColor Red; $script:Fail++ }
}

# Two hidden entries that must match and be 12+ chars; returns a SecureString or $null.
function Get-NewPw {
    for ($i = 0; $i -lt 3; $i++) {
        $a = Read-Host '  new password (12+ chars)' -AsSecureString
        $b = Read-Host '  again' -AsSecureString
        $x = (New-Object Net.NetworkCredential('', $a)).Password
        $y = (New-Object Net.NetworkCredential('', $b)).Password
        $ok = ($a.Length -ge 12) -and ($x -ceq $y)
        $x = $null; $y = $null
        if ($ok) { return $a }
        Write-Host '  entries differ or too short, try again'
    }
}

# Random password from the OS CSPRNG. Nothing here is guessable from reading this file:
# the alphabet is public, the output is not. Rejection sampling avoids modulo bias.
function New-RandomPw([int]$Len = 16) {
    # letters and digits only (no 0 O 1 l I): symbols are easy to mistype on a VM console keyboard,
    # and with no VM revert a wrong transcription would lock the account out.
    $alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $max = 256 - (256 % $alpha.Length)
    $one = New-Object byte[] 1
    do {
        $sb = New-Object Text.StringBuilder
        while ($sb.Length -lt $Len) {
            $rng.GetBytes($one)
            if ($one[0] -lt $max) { [void]$sb.Append($alpha[$one[0] % $alpha.Length]) }
        }
        $p = $sb.ToString()
    } until ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '\d')
    $rng.Dispose()
    $p
}

if (-not $DryRun) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    # Reports list local admins and settings: only Administrators and SYSTEM may read them.
    icacls $OutDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE) { throw "could not lock the report folder $OutDir (icacls exit $LASTEXITCODE); stopping before anything is changed" }
    # Snapshot what -Undo needs beyond registry, services and firewall. Each item is separate so one failure loses only itself.
    T { $script:Misc.GuestWasEnabled = [bool](Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' -and $_.Enabled }) }
    T { $script:Misc.Smb1 = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol }
    T {
        $af = Join-Path $OutDir 'audit-before.csv'
        auditpol /backup "/file:$af" | Out-Null   # quoted as one argument: a bare (Join-Path) would split into two
        if ($LASTEXITCODE -or -not (Test-Path $af)) { throw 'audit policy backup failed: -Undo cannot restore the audit policy' }
    }
    T {
        $mp = Get-MpPreference
        $script:Misc.Mp = @{
            Rtm = [bool]$mp.DisableRealtimeMonitoring; Beh = [bool]$mp.DisableBehaviorMonitoring; Pua = [int]$mp.PUAProtection
            AsrIds = $(if ($mp.AttackSurfaceReductionRules_Ids) { @($mp.AttackSurfaceReductionRules_Ids) } else { @() })
            AsrActions = $(if ($mp.AttackSurfaceReductionRules_Actions) { @($mp.AttackSurfaceReductionRules_Actions) } else { @() })
        }
    }
    T {
        $script:Misc.Logs = @{
            Security = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
            PS = (Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational').MaximumSizeInBytes
        }
    }
}

# ---------- steps ----------
Step accounts 'accounts: disable Guest, reset passwords you choose (no renames, rules forbid it)' {
    $users = @(Get-LocalUser)
    Write-Host '  For scored or shared team accounts, and the account you are logged in as unless you are sure, just press Enter (no change).' -ForegroundColor Yellow
    foreach ($g in ($users | Where-Object { $_.SID.Value -like '*-501' -and $_.Enabled })) { T { Disable-LocalUser -SID $g.SID } }
    foreach ($u in ($users | Where-Object { $_.Enabled -and $_.SID.Value -notlike '*-501' })) {
        if ("$($u.PrincipalSource)" -in 'MicrosoftAccount', 'AzureAD') {
            Write-Host "  '$($u.Name)' is a $($u.PrincipalSource) account: Set-LocalUser cannot set its password. Skipped." -ForegroundColor Yellow
            continue
        }
        $m = (Read-Host "Account '$($u.Name)': [g]enerate random password, [t]ype your own, [N]o change").ToLower()
        if ($m -eq 'g') {
            $plain = New-RandomPw $PwLength
            Write-Host "  new password for '$($u.Name)': $plain" -ForegroundColor Yellow
            Read-Host '  write it on paper, then type "written" and Enter' | Out-Null
            $pw = ConvertTo-SecureString $plain -AsPlainText -Force
            $plain = $null
            $script:setOk = $false
            T { Set-LocalUser -Name $u.Name -Password $pw -ErrorAction Stop; [void]$script:PwChanged.Add($u.Name); $script:setOk = $true }
            if ($script:setOk) {
                Clear-Host   # only after success, so a [FAIL] is never wiped
                # runas fails on the Proxmox console ("Unable to acquire user password", Nov 9), so check the password with a hidden prompt instead. Type each line on its own.
                Write-Host "  '$($u.Name)' changed. Before you log out of the last admin session, prove it works with these three lines:" -ForegroundColor Yellow
                Write-Host '    Add-Type -AssemblyName System.DirectoryServices.AccountManagement' -ForegroundColor Yellow
                Write-Host '    $p = Read-Host pw -AsSecureString' -ForegroundColor Yellow
                Write-Host "    (New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine')).ValidateCredentials('$($u.Name)', [Net.NetworkCredential]::new('',`$p).Password)" -ForegroundColor Yellow
            }
        } elseif ($m -eq 't') {
            $pw = Get-NewPw
            if (-not $pw) { Write-Host "  '$($u.Name)' left unchanged"; continue }
            T { Set-LocalUser -Name $u.Name -Password $pw; [void]$script:PwChanged.Add($u.Name); Write-Host "  '$($u.Name)' changed. Write it on paper now." }
        }
    }
    Ck 'Guest disabled' { -not (Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' -and $_.Enabled }) }
}

Step fw 'firewall: all profiles on, inbound blocked, ping allowed, discovery/assistance/file sharing rules off' {
    $wfw = Join-Path $OutDir 'fw-before.wfw'
    netsh advfirewall export $wfw | Out-Null
    if ($LASTEXITCODE -or -not (Test-Path $wfw)) { throw 'firewall export failed: skipping the firewall step so there is always a way back' }
    Get-NetFirewallProfile | ForEach-Object { Write-Host "  before: $($_.Name) enabled=$($_.Enabled) in=$($_.DefaultInboundAction) out=$($_.DefaultOutboundAction)" }
    $lp = @(3389, 5985, 5986, 445 | Where-Object { Get-NetTCPConnection -State Listen -LocalPort $_ -ErrorAction SilentlyContinue })
    if ($lp.Count) {
        Write-Host "  note: listening on port(s) $($lp -join ', '). RDP/WinRM rules are left as found, but SMB (445) inbound is closed by the file-sharing group below; White/Green Team may ask for access (packet p17 rule 4)." -ForegroundColor Yellow
    }
    T { Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow }
    T {
        if (-not (Get-NetFirewallRule -DisplayName 'CDC ICMP echo in' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'CDC ICMP echo in' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null
        }
        if (-not (Get-NetFirewallRule -DisplayName 'CDC ICMPv6 echo in' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'CDC ICMPv6 echo in' -Direction Inbound -Protocol ICMPv6 -IcmpType 128 -Action Allow -Profile Any | Out-Null
        }
    }
    # ponytail: group names are English-only; on another language the loop finds nothing and says nothing
    $groups = @('Network Discovery', 'Remote Assistance') + $(if ($KeepFileSharing) { @() } else { @('File and Printer Sharing') })
    if ($KeepFileSharing) { Write-Host '  note: -KeepFileSharing: File and Printer Sharing rules left as found' }
    foreach ($g in $groups) {
        Disable-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue
    }
    # The loop above hides errors, so prove the groups exist and are off. Zero rules found means the group names differ on this build.
    $grp = @(Get-NetFirewallRule -DisplayGroup $groups -ErrorAction SilentlyContinue)
    Ck "firewall groups found ($($grp.Count) rules) and all disabled" { $grp.Count -gt 0 -and -not ($grp | Where-Object { $_.Enabled -eq 'True' }) }
    Ck 'profiles on and inbound blocked (FAIL here on a domain box usually means GPO overrides)' {
        -not (Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' })
    }
    Ck 'ICMPv4 and ICMPv6 echo rules present and enabled' {
        (@(Get-NetFirewallRule -DisplayName 'CDC ICMP echo in', 'CDC ICMPv6 echo in' | Where-Object { $_.Enabled -eq 'True' })).Count -eq 2
    }
}

Step velo "Velociraptor: allow inbound TCP $VeloFrontendPort (clients enrol) and $(if ($VeloFilePort) { "$VeloFilePort (client files)" } else { 'no file port' }) from any source; GUI $VeloGuiPort $(if ($OpenGuiPort) { 'also opened (-OpenGuiPort)' } else { 'stays localhost-only' })" {
    # Any source on purpose: packet p17 rule 9 penalizes source-IP filtering, and clients can sit on any internal subnet.
    $want = @(@{ Name = "CDC Velociraptor frontend $VeloFrontendPort"; Port = $VeloFrontendPort })
    if ($VeloFilePort) { $want += @{ Name = "CDC Velociraptor files $VeloFilePort"; Port = $VeloFilePort } }   # python -m http.server for client.config.yaml and the installer
    if ($OpenGuiPort) { $want += @{ Name = "CDC Velociraptor GUI $VeloGuiPort"; Port = $VeloGuiPort } }
    foreach ($r in $want) {
        T {
            if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol TCP -LocalPort $r.Port -Action Allow -Profile Any | Out-Null
                $script:Misc.VeloRules += $r.Name
            }
        }
        Ck "inbound TCP $($r.Port) allow rule present and enabled" { @(Get-NetFirewallRule -DisplayName $r.Name | Where-Object { $_.Enabled -eq 'True' }).Count -ge 1 }
    }
    foreach ($p in $VeloFrontendPort, $VeloGuiPort) {
        $l = @(Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue)
        if ($l.Count) { Write-Host "  info: port $p is listening on $((@($l.LocalAddress) | Sort-Object -Unique) -join ', ')" }
        else { Write-Host "  info: nothing is listening on $p yet; start Velociraptor, then run Test-WorkstationHealth-Win11.ps1 -Velociraptor" }
    }
    if (-not $OpenGuiPort) {
        Write-Host "  note: no inbound rule for GUI port $VeloGuiPort on purpose. Browse to https://127.0.0.1:$VeloGuiPort on this box (untested: local connections should not need a rule). Use -OpenGuiPort only if bind_address was changed to 0.0.0.0 and the team accepts the exposure."
    }
    Write-Host '  note: a group policy or the Palo Alto can still block 8000 from other machines; the health check run from a client shows it.'
}

Step proto 'protocols: SMB1, LLMNR, mDNS, NetBIOS, WDigest, LM hash, NTLMv2 only, anonymous enumeration, AutoRun' {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    T { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' EnableMDNS 0
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0
    Set-Reg $lsa NoLMHash 1
    Set-Reg $lsa LmCompatibilityLevel 5
    Set-Reg $lsa RestrictAnonymous 1
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' DisableAutoplay 1
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0
    T { Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-Reg $_.PSPath NetbiosOptions 2 } }
    Ck 'SMB1 off'  { -not (Get-SmbServerConfiguration).EnableSMB1Protocol }
    Ck 'LLMNR off' { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient').EnableMulticast -eq 0 }
    Ck 'WDigest off' { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential -eq 0 }
    Ck 'NTLMv2 only' { (Get-ItemProperty $lsa).LmCompatibilityLevel -eq 5 }
    Ck 'NetBIOS off on every interface key' { -not (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | Where-Object { (Get-ItemProperty $_.PSPath).NetbiosOptions -ne 2 }) }
    Ck 'Remote Assistance off' { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance').fAllowToGetHelp -eq 0 }
}

Step services 'services: stop and disable Print Spooler, Remote Registry, SSDP, UPnP' {
    foreach ($n in 'Spooler', 'RemoteRegistry', 'SSDPSRV', 'upnphost', 'TlntSvr', 'SimpTcp') {
        $s = Get-Service $n -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        [void]$script:Svc.Add([pscustomobject]@{ Name = $n; Old = "$($s.StartType)"; Running = ($s.Status -eq 'Running') })
        T { Stop-Service $n -Force -ErrorAction SilentlyContinue; Set-Service $n -StartupType Disabled }
    }
    Write-Host '  note: Print Spooler is now disabled. Re-enable it (Set-Service Spooler -StartupType Automatic; Start-Service Spooler) if an inject needs printing.'
    Ck 'Spooler and Remote Registry disabled' {
        (Get-Service Spooler, RemoteRegistry | Where-Object { $_.StartType -ne 'Disabled' }).Count -eq 0
    }
}

Step defender 'Defender: real-time on, PUA audit, ASR (LSASS and Office children block, obfuscated scripts audit), background quick scan' {
    $asr = $AsrIds
    # PUA in audit, not block: tools staged for Velociraptor artifacts could otherwise be quarantined.
    T { Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -PUAProtection AuditMode }
    T { Add-MpPreference -AttackSurfaceReductionRules_Ids $asr -AttackSurfaceReductionRules_Actions $AsrActs }
    T { Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile -Command Start-MpScan -ScanType QuickScan' }
    T { Write-Host "  signatures last updated: $((Get-MpComputerStatus).AntivirusSignatureLastUpdated) (not updated here, no internet by design)" }
    Ck 'Defender real-time on' { -not (Get-MpPreference).DisableRealtimeMonitoring }
    # ASR rules do not work when another antivirus has put Defender in passive mode. Older platforms lack the property, so absent counts as fine.
    Ck 'Defender is the active antivirus, not passive' { $m = (Get-MpComputerStatus).AMRunningMode; (-not $m) -or ("$m" -eq 'Normal') }
    Ck 'ASR LSASS rule set to block' {
        $p = Get-MpPreference; $ids = @($p.AttackSurfaceReductionRules_Ids | ForEach-Object { "$_".ToLower() })
        $ix = [array]::IndexOf($ids, $asr[0]); $ix -ge 0 -and "$(@($p.AttackSurfaceReductionRules_Actions)[$ix])" -in '1', 'Enabled'
    }
}

Step audit 'logging: audit policy, command lines, PowerShell script blocks, larger event logs' {
    # ponytail: auditpol subcategory names are English-only; a failure is counted and printed
    foreach ($c in 'Logon', 'Logoff', 'Special Logon', 'Account Lockout', 'Credential Validation', 'User Account Management', 'Security Group Management',
                   'Process Creation', 'Audit Policy Change', 'MPSSVC Rule-Level Policy Change', 'Security System Extension',
                   'Other Object Access Events', 'File Share') {   # Sensitive Privilege Use left out: 4673/4674 flood the log
        auditpol /set /subcategory:"$c" /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE) { Write-Host "  [FAIL] auditpol: $c" -ForegroundColor Red; $script:Fail++ }
    }
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1
    wevtutil sl Security /ms:268435456
    wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:67108864
    auditpol /get /category:* | Out-File (Join-Path $OutDir 'audit-after.txt')   # evidence for audit injects
    Ck 'Security log at least 256 MB' { (Get-WinEvent -ListLog Security).MaximumSizeInBytes -ge 268435456 }
    Ck 'process creation audited' { (auditpol /get /subcategory:'Process Creation') -match 'Success' }
    Ck 'command-line capture on' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit').ProcessCreationIncludeCmdLine_Enabled -eq 1 }
}

# ---------- finish ----------
if (-not $DryRun) {
    $script:Misc.PwAccounts = @($script:PwChanged)
    @{ Reg = $script:Reg; Svc = $script:Svc; Misc = $script:Misc } | Export-Clixml -Depth 6 (Join-Path $OutDir 'undo.xml')
    Write-Host "`nReport and undo data: $OutDir   (undo: .\Harden-Win11Wks.ps1 -Undo '$OutDir')"
}
if ($script:Fail) { Write-Host "$script:Fail problem(s), read the [FAIL] lines above." -ForegroundColor Red }
else { Write-Host 'No problems.' -ForegroundColor Green }
