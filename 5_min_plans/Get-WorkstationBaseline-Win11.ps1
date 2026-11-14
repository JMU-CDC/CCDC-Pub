<#
.SYNOPSIS
  Read-only security baseline of the Windows 11 workstation that also runs the Velociraptor server (11 checks + optional diff).
.DESCRIPTION
  Windows 11 edition of Get-WorkstationBaseline.ps1 (see Win11-Scripts.SPEC.md). The firewall check also reports Velociraptor ports 8000 and 8889.
  Implements Get-WorkstationBaseline.SPEC.md (spec date 2026-10-12).
  Windows PowerShell 5.1, offline, changes nothing except its own output folder.
  Exit code is always 0, even with findings.
.PARAMETER OutDir
  Output folder, created if absent.
.PARAMETER Compare
  Earlier baseline folder; prints lines added since then for checks 2, 6, 7, 9.
.PARAMETER Quiet
  Skip the console summary, write files only.
#>
param(
    [string]$OutDir = "C:\Reports\baseline-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [string]$Compare = '',
    [switch]$Quiet
)

# Constrained Language Mode (Smart App Control or an application-control policy) breaks the .NET calls below. Stop with a clear message.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw "PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode (Smart App Control or an application-control policy is on). This script needs FullLanguage. Do not run it; tell the team."
}

$ErrorActionPreference = 'Stop'   # so try/catch sees failures; noisy spots use -ErrorAction SilentlyContinue
$NL = [Environment]::NewLine
$script:Results = New-Object System.Collections.ArrayList
$script:Ev = @{}      # snippets reused by check 11
$script:Stat = @{}    # per-check scratch values set inside Section blocks
$script:ProcCache = @{}      # pid -> @(name, path) cache
$script:SecFail = New-Object System.Collections.ArrayList   # sections that threw; their file text is n/a
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------- helpers ----------
function KV($k, $v) { '{0,-18}: {1}' -f $k, $v }

function Fmt($o) {
    if ($null -eq $o -or @($o).Count -eq 0) { return '(none)' }
    ($o | Format-Table -AutoSize | Out-String -Width 4096).Trim()
}

function FmtL($o) { ($o | Format-List | Out-String -Width 4096).Trim() }

# Throw if a cmdlet is missing, so the check (or section) reports n/a.
function Need($cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "cmdlet $cmd not available on this OS" }
}

# Run a block; return its value or an n/a string.
function Safe([scriptblock]$sb) {
    try { & $sb } catch { 'n/a: ' + $_.Exception.Message }
}

# Native commands (query, net) write to stderr on normal 'nothing found' answers; under Stop that would throw.
function Native([scriptblock]$sb) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $sb } finally { $ErrorActionPreference = $old }
}

# Registry read that returns $null when the key or value is absent.
function RegVal($path, $name) {
    try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null }
}

# One titled block of a report file; a failing block becomes n/a, the rest continues.
function Section($Title, [scriptblock]$Body) {
    try { $r = (& $Body | Out-String).TrimEnd() } catch { $r = 'n/a: ' + $_.Exception.Message; [void]$script:SecFail.Add($Title) }
    if (-not $r) { $r = '(none)' }
    "== $Title$NL$r$NL"
}

function Res($status, $detail, $text) {
    [pscustomobject]@{ Status = $status; Detail = $detail; Text = $text }
}

function Add-Result($name, $status, $detail) {
    $d = ("$detail" -replace '\s+', ' ').Trim()
    [void]$script:Results.Add([pscustomobject]@{ Name = $name; Status = $status; Detail = $d })
}

# Runs one check function; on failure writes "n/a: <reason>" to its file and moves on.
function Invoke-Check($name, $file, $fn) {
    $script:Stat = @{}
    $path = Join-Path $OutDir $file
    try {
        $r = & $fn
        Set-Content -Path $path -Value $r.Text -Encoding UTF8
        Add-Result $name $r.Status $r.Detail
    } catch {
        $msg = 'n/a: ' + $_.Exception.Message
        try { Set-Content -Path $path -Value $msg -Encoding UTF8 } catch { Write-Warning "cannot write $file" }
        Add-Result $name 'unknown' $msg
    }
}

# Process name/path lookup with cache (Get-Process -Id, path may be denied).
function Get-ProcInfo($id) {
    if (-not $script:ProcCache.ContainsKey($id)) {
        $n = ''; $p = ''
        try {
            $pr = Get-Process -Id $id -ErrorAction Stop
            $n = $pr.ProcessName
            try { $p = $pr.Path } catch { $p = '' }
        } catch { $n = '(exited)' }
        $script:ProcCache[$id] = @($n, "$p")
    }
    $script:ProcCache[$id]
}

function Test-Review($p, $name) {
    # lsass/System/services have no readable path but are normal owners of the dynamic RPC ports
    if (-not $p -and $name -in 'lsass', 'System', 'services', 'wininit') { '' }
    elseif (-not $p) { 'review?' }
    elseif ($p -notmatch '^"?(C:\\Windows\\System32|C:\\Program Files( \(x86\))?)\\') { 'review' }
    else { '' }
}

# Effective firewall profile: the policy-merged ActiveStore reports 'NotConfigured' for anything
# no Group Policy sets, so fall back to the local (persistent) value, which is what really applies.
function Get-EffProfiles {
    foreach ($n in 'Domain', 'Private', 'Public') {
        $a = Get-NetFirewallProfile -Name $n -PolicyStore ActiveStore
        $l = Get-NetFirewallProfile -Name $n -PolicyStore PersistentStore
        $o = [ordered]@{ Name = $n }
        foreach ($prop in 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'AllowInboundRules') {
            $o[$prop] = if ($a -and "$($a.$prop)" -ne 'NotConfigured') { "$($a.$prop)" } else { "$($l.$prop)" }
        }
        [pscustomobject]$o
    }
}

# ---------- checks ----------
function Check-System {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $el = 'no'; if ($script:IsAdmin) { $el = 'yes' }
    $t = @(
        (KV 'OS name' $os.Caption),
        (KV 'Version' $os.Version),
        (KV 'Build' $os.BuildNumber),
        (KV 'Hostname' $cs.Name),
        (KV 'Domain/Workgroup' $cs.Domain),
        (KV 'PartOfDomain' $cs.PartOfDomain),
        (KV 'Last boot' $os.LastBootUpTime),
        (KV 'Current user' ([Security.Principal.WindowsIdentity]::GetCurrent().Name)),
        (KV 'Elevated' $el)
    ) -join $NL
    $script:Ev.sys = $t
    if ($script:IsAdmin) { return (Res 'ok' "$($os.Caption) build $($os.BuildNumber), elevated" $t) }
    Res 'finding' 'not elevated, results may be incomplete' $t
}

function Check-Accounts {
    $script:Stat.guest = $false
    $script:Stat.names = @()
    $t1 = Section 'Local users' {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $u = @(Get-LocalUser)
            # Guest is the account with RID 501, whatever its localized name
            if ($u | Where-Object { $_.SID.Value -like '*-501' -and $_.Enabled }) { $script:Stat.guest = $true }
            Fmt ($u | Select-Object Name, Enabled, LastLogon, PasswordLastSet)
        } else {
            if (net user guest 2>$null | Select-String 'Account active\s+Yes') { $script:Stat.guest = $true }
            (net user 2>$null) -join $NL
        }
    }
    $t2 = Section 'Administrators members' {
        $names = @(); $done = $false; $out = ''
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            try {
                $m = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
                $names = @($m | ForEach-Object { [string]$_.Name })
                $out = Fmt ($m | Select-Object Name, ObjectClass, PrincipalSource)
                $done = $true
            } catch { $done = $false }   # orphaned SIDs etc: use net.exe
        }
        if (-not $done) {
            $in = $false
            foreach ($l in (Native { net localgroup Administrators 2>$null })) {
                if ($l -like '---*') { $in = $true; continue }
                if ($l -like 'The command completed*') { break }
                if ($in -and $l.Trim()) { $names += $l.Trim() }
            }
            $out = $names -join $NL
        }
        $script:Stat.names = $names
        $out
    }
    $t3 = Section 'Logged-on sessions' {
        $q = @(Native { query user 2>$null })
        if ($q.Count -eq 0) { '(none reported)' } else { $q -join $NL }
    }
    # Review list: anything not named Administrator or the current user
    $review = @($script:Stat.names | Where-Object {
        $leaf = ($_ -split '\\')[-1]
        $isOwnAdmin = ($_ -ieq "$env:COMPUTERNAME\Administrator") -or ($_ -ieq 'Administrator')
        -not $isOwnAdmin -and $leaf -ne $env:USERNAME
    })
    $t4 = "== Review (admins other than Administrator/current user)$NL" + $(if ($review.Count) { $review -join $NL } else { '(none)' }) + $NL
    $text = $t1 + $NL + $t2 + $NL + $t4 + $NL + $t3
    if ($script:Stat.guest) { return (Res 'finding' 'Guest account enabled' $text) }
    if ($review.Count) { return (Res 'finding' "$($review.Count) admin member(s) other than Administrator/you to review: $($review -join ', ')" $text) }
    Res 'ok' 'Guest disabled, no unexpected admins' $text
}

function Check-Firewall {
    Need Get-NetFirewallProfile
    $p = @(Get-EffProfiles)
    $bad = @($p | Where-Object { "$($_.Enabled)" -eq 'False' -or "$($_.DefaultInboundAction)" -eq 'Allow' })
    $pt = Fmt ($p | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    $script:Ev.fw = $pt
    $rt = Section 'Enabled inbound allow rules' {
        Need Get-NetFirewallRule
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow)
        # bulk-load filters once (per-rule queries are far too slow); InstanceID matches rule Name
        $pf = @{}; $af = @{}; $rf = @{}
        foreach ($x in @(Get-NetFirewallPortFilter -PolicyStore ActiveStore)) { $pf[$x.InstanceID] = $x }
        foreach ($x in @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore)) { $af[$x.InstanceID] = $x }
        foreach ($x in @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore)) { $rf[$x.InstanceID] = $x }
        $rows = foreach ($r in $rules) {
            [pscustomobject]@{
                Name          = $r.DisplayName
                Program       = $af[$r.Name].Program
                Protocol      = $pf[$r.Name].Protocol
                LocalPort     = ($pf[$r.Name].LocalPort -join ',')
                RemoteAddress = ($rf[$r.Name].RemoteAddress -join ',')
            }
        }
        $script:Stat.rules = @($rules).Count
        Fmt ($rows | Sort-Object Name)
    }
    # Velociraptor on this box: clients need inbound 8000; the GUI on 8889 should listen on localhost only.
    $vr = Section 'Velociraptor ports (expected: 8000 open inbound, 8889 localhost only)' {
        $out = @()
        foreach ($port in 8000, 8889) {
            $l = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
            $addr = @($l | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique)
            if ($l.Count) { $out += "port ${port}: listening on $($addr -join ', ')" } else { $out += "port ${port}: not listening" }
            if ($port -eq 8000) { $script:Stat.frontListen = [bool]$l.Count }
            if ($port -eq 8889 -and @($addr | Where-Object { $_ -notin '127.0.0.1', '::1' }).Count) { $script:Stat.guiExposed = $true }
        }
        $ids = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore | Where-Object { @($_.LocalPort) -contains '8000' -and "$($_.Protocol)" -in 'TCP', '6' } | ForEach-Object { $_.InstanceID })
        $ids += @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore | Where-Object { "$($_.Program)" -like '*velociraptor*' } | ForEach-Object { $_.InstanceID })   # program rule from the "Allow access" pop-up
        $allow = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow | Where-Object { $ids -contains $_.Name })
        $script:Stat.frontAllowed = ($allow.Count -gt 0)
        $out += "inbound allow rule for TCP 8000: $(if ($allow.Count) { ($allow | ForEach-Object { $_.DisplayName }) -join '; ' } else { 'none' })"
        $out
    }
    $text = "== Profiles$NL$pt$NL$NL$rt$NL$vr"
    $why = @()
    if ($bad.Count) { $why += "profile off or inbound Allow: $((($bad | ForEach-Object { $_.Name }) -join ', '))" }
    if ($script:Stat.guiExposed) { $why += 'Velociraptor GUI 8889 listens beyond localhost' }
    if ($script:Stat.frontListen -and -not $script:Stat.frontAllowed) { $why += 'Velociraptor listens on 8000 but no inbound allow rule exists, clients cannot enrol' }
    if ($why.Count) { return (Res 'finding' ($why -join '; ') $text) }
    Res 'ok' "all profiles on, inbound not Allow, $($script:Stat.rules) allow rules" $text
}

function Check-Defender {
    Need Get-MpComputerStatus
    $s = Get-MpComputerStatus
    $age = $null
    if ($s.AntivirusSignatureLastUpdated) { $age = ((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays }
    $main = FmtL ($s | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AMRunningMode, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanStartTime, QuickScanEndTime)
    $script:Ev.def = $main
    $other = Section 'Registered AV products (SecurityCenter2)' {
        Fmt (Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | Select-Object displayName, productState)
    }
    $text = "== Defender$NL$main$NL$NL$other"
    $why = @()
    if (-not $s.RealTimeProtectionEnabled) { $why += 'real-time off' }
    # ASR rules do not work in passive mode (another antivirus is primary); older platforms lack the property.
    if ($s.AMRunningMode -and "$($s.AMRunningMode)" -ne 'Normal') { $why += "running mode $($s.AMRunningMode), ASR rules inactive" }
    if ($null -ne $age -and $age -gt 3) { $why += ('signatures {0:N0} days old' -f $age) }
    if ($why.Count) { return (Res 'finding' ($why -join ', ') $text) }
    Res 'ok' 'real-time on, signatures current' $text
}

function Check-Updates {
    Need Get-HotFix
    $hf = @(Get-HotFix | Sort-Object InstalledOn -Descending)
    $top = @($hf | Select-Object -First 10 HotFixID, Description, InstalledOn, InstalledBy)
    $script:Ev.hf = Fmt ($top | Select-Object -First 1)
    $svc = Section 'Windows Update service' { Fmt (Get-Service wuauserv | Select-Object Name, Status, StartType) }
    $text = "== Most recent 10 hotfixes$NL$(Fmt $top)$NL$NL$svc"
    $newest = $hf | Where-Object { $_.InstalledOn } | Select-Object -First 1
    if (-not $newest) { return (Res 'unknown' 'no hotfix with an install date' $text) }
    $days = ((Get-Date) - [datetime]$newest.InstalledOn).TotalDays
    if ($days -gt 60) { return (Res 'finding' ('newest hotfix {0:N0} days old' -f $days) $text) }
    Res 'ok' ('newest hotfix {0:N0} days old' -f $days) $text
}

function Check-Network {
    $script:Stat.review = 0
    $listen = Section 'Listening TCP/UDP' {
        $tcp = foreach ($c in @(Get-NetTCPConnection -State Listen)) {
            $i = Get-ProcInfo $c.OwningProcess
            [pscustomobject]@{ Proto = 'TCP'; Local = $c.LocalAddress; Port = $c.LocalPort; Process = $i[0]; Path = $i[1]; Mark = (Test-Review $i[1] $i[0]) }
        }
        $udp = foreach ($c in @(Get-NetUDPEndpoint)) {
            $i = Get-ProcInfo $c.OwningProcess
            [pscustomobject]@{ Proto = 'UDP'; Local = $c.LocalAddress; Port = $c.LocalPort; Process = $i[0]; Path = $i[1]; Mark = (Test-Review $i[1] $i[0]) }
        }
        $all = @(@($tcp) + @($udp) | Where-Object { $_ })
        $script:Stat.n = @($all).Count
        $script:Stat.review = @($all | Where-Object { $_.Mark }).Count
        Fmt ($all | Sort-Object Proto, Port)
    }
    $est = Section 'Established TCP connections' {
        $rows = @(foreach ($c in @(Get-NetTCPConnection -State Established)) {
            $i = Get-ProcInfo $c.OwningProcess
            [pscustomobject]@{ Local = "$($c.LocalAddress):$($c.LocalPort)"; Remote = "$($c.RemoteAddress):$($c.RemotePort)"; Process = $i[0]; Path = $i[1] }
        })
        $script:Stat.est = @($rows).Count
        Fmt ($rows | Sort-Object Process)
    }
    Res 'ok' "$($script:Stat.n) listeners ($($script:Stat.review) outside System32/Program Files), $($script:Stat.est) established" ($listen + $NL + $est)
}

function Check-Persistence {
    $script:Stat.n = 0
    $script:Stat.wmi = 0
    $run = Section 'Run/RunOnce keys' {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        $rows = @(foreach ($k in $keys) {
            if (Test-Path $k) {
                foreach ($pp in (Get-ItemProperty -Path $k).PSObject.Properties) {
                    if (@('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') -notcontains $pp.Name) { "$k | $($pp.Name) | $($pp.Value)" }
                }
            }
        })
        $script:Stat.n += $rows.Count
        $rows
    }
    $start = Section 'Startup folders' {
        $rows = @(foreach ($d in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")) {
            if (Test-Path $d) {
                Get-ChildItem -Path $d -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { $_.FullName }
            }
        })
        $script:Stat.n += $rows.Count
        $rows
    }
    $tasks = Section 'Non-Microsoft scheduled tasks' {
        Need Get-ScheduledTask
        $rows = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
            $a = (@($_.Actions) | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join '; '
            "$($_.TaskPath)$($_.TaskName) | $a"
        })
        $script:Stat.n += $rows.Count
        $rows | Sort-Object
    }
    $svcs = Section 'Auto-start services outside System32/Program Files' {
        $rows = @(Get-CimInstance Win32_Service | Where-Object {
            $_.StartMode -eq 'Auto' -and $_.PathName -and $_.PathName -notmatch '^"?(C:\\Windows\\System32|C:\\Program Files( \(x86\))?)\\'
        } | ForEach-Object { "$($_.Name) | $($_.PathName) | $($_.StartName)" })
        $script:Stat.n += $rows.Count
        $rows | Sort-Object
    }
    # Unfiltered lists exist only so -Compare sees a new service or task wherever the red team puts it.
    $allsvc = Section 'All services (for -Compare)' {
        Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name) | $($_.StartMode) | $($_.PathName) | $($_.StartName)" } | Sort-Object
    }
    $alltask = Section 'All scheduled tasks (for -Compare)' {
        Need Get-ScheduledTask
        Get-ScheduledTask | ForEach-Object { "$($_.TaskPath)$($_.TaskName) | " + ((@($_.Actions) | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join '; ') } | Sort-Object
    }
    $wmi = Section 'WMI event subscriptions (root\subscription)' {
        foreach ($c in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
            # the stock "SCM Event Log" filter/consumer/binding exists on clean Windows; ignore it
            $items = @(Get-CimInstance -Namespace 'root\subscription' -ClassName $c | Where-Object {
                $it = $_   # inside switch, $_ is the switch value, not this object
                $stock = switch ($c) {
                    '__EventFilter' { $it.Name -ceq 'SCM Event Log Filter' -and $it.Query -ceq 'select * from MSFT_SCMEventLogEvent' }
                    '__EventConsumer' { $it.CimClass.CimClassName -eq 'NTEventLogEventConsumer' -and $it.Name -ceq 'SCM Event Log Consumer' }
                    default { "$($it.Filter)" -cmatch 'Name="SCM Event Log Filter"' -and "$($it.Consumer)" -cmatch 'Name="SCM Event Log Consumer"' }
                }
                -not $stock
            })
            $script:Stat.wmi += $items.Count
            "-- $c : $($items.Count)"
            foreach ($i in $items) {
                $bits = foreach ($pn in 'Name', 'Query', 'CommandLineTemplate', 'ExecutablePath', 'ScriptText', 'Filter', 'Consumer') {
                    $v = $i.$pn
                    if ($v) { "$pn=$v" }
                }
                "   $($i.CimClass.CimClassName) | $($bits -join ' | ')"
            }
        }
    }
    $text = $run + $NL + $start + $NL + $tasks + $NL + $svcs + $NL + $wmi + $NL + $allsvc + $NL + $alltask
    $n = $script:Stat.n; $w = $script:Stat.wmi
    if ($w -gt 0) { return (Res 'finding' "$w WMI subscription object(s), $n other items to review" $text) }
    Res 'ok' "$n items to review, no WMI subscriptions" $text
}

function Check-Protocols {
    $script:ProtoRows = New-Object System.Collections.ArrayList
    $script:F = New-Object System.Collections.ArrayList
    function Row($s, $v, $bad) {
        $n = ''
        if ($bad) { $n = 'FINDING'; [void]$script:F.Add($s) }
        if ($null -eq $v -or "$v" -eq '') { $v = '(unset)' }
        [void]$script:ProtoRows.Add([pscustomobject]@{ Setting = $s; Value = "$v"; Note = $n })
    }
    $smb1 = Safe { (Get-SmbServerConfiguration).EnableSMB1Protocol }
    Row 'SMBv1 server enabled' $smb1 ("$smb1" -eq 'True')
    Row 'SMB signing required' (Safe { (Get-SmbServerConfiguration).RequireSecuritySignature }) $false
    $v = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    Row 'LLMNR policy (EnableMulticast)' $v ("$v" -ne '0')
    try {
        foreach ($a in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')) {
            Row "NetBIOS: $($a.Description)" $a.TcpipNetbiosOptions ("$($a.TcpipNetbiosOptions)" -ne '2')
        }
    } catch { Row 'NetBIOS per adapter' ('n/a: ' + $_.Exception.Message) $false }
    $v = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    Row 'WDigest UseLogonCredential' $v ("$v" -eq '1')
    $v = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    Row 'LSA LmCompatibilityLevel' $v ($null -eq $v -or [int]$v -lt 5)
    $v = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $rdp = 'unknown'; if ("$v" -eq '0') { $rdp = 'on' } elseif ("$v" -eq '1') { $rdp = 'off' }
    Row 'RDP enabled (info)' $rdp $false
    $v = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    Row 'RDP NLA (UserAuthentication)' $v ("$v" -eq '0')
    $winrm = Safe { (Get-Service WinRM).Status }
    Row 'WinRM service (info)' $winrm $false
    Row 'Remote Registry service (info)' (Safe { (Get-Service RemoteRegistry).Status }) $false
    $text = Fmt $script:ProtoRows
    $info = "RDP $rdp, WinRM $winrm"
    if ($script:F.Count) { return (Res 'finding' "$($script:F -join ', '); $info" $text) }
    Res 'ok' "no weak settings; $info" $text
}

function Check-Shares {
    Need Get-SmbShare
    $sh = @(Get-SmbShare)
    $odd = @($sh | Where-Object { @('C$', 'ADMIN$', 'IPC$') -notcontains $_.Name })
    $acc = Section 'Share access' {
        $rows = foreach ($s in $sh) { try { Get-SmbShareAccess -Name $s.Name -ErrorAction Stop } catch { [pscustomobject]@{ Name = $s.Name; AccountName = 'n/a'; AccessControlType = ''; AccessRight = '' } } }
        Fmt ($rows | Select-Object Name, AccountName, AccessControlType, AccessRight)
    }
    $text = "== Shares$NL$(Fmt ($sh | Select-Object Name, Path, Description))$NL$NL$acc"
    if ($odd.Count) { return (Res 'finding' "non-default share(s): $((($odd | ForEach-Object { $_.Name }) -join ', '))" $text) }
    Res 'ok' 'only C$, ADMIN$, IPC$' $text
}

function Check-Recent {
    $cap = 5000
    $cut = (Get-Date).AddHours(-24)
    $ext = '.exe', '.dll', '.ps1', '.bat', '.vbs', '.js', '.lnk'
    $script:Stat.trunc = $false
    $files = Section 'Files created/modified in last 24 h' {
        $dirs = @('C:\Users\Public', 'C:\Windows\Temp', $env:TEMP, 'C:\ProgramData') | Where-Object { $_ } | Select-Object -Unique
        $found = @()
        foreach ($d in $dirs) {
            if (-not (Test-Path $d)) { continue }
            $left = $cap + 1 - $found.Count
            if ($left -le 0) { break }
            $found += @(Get-ChildItem -Path $d -Force -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { ($ext -contains $_.Extension) -and ($_.CreationTime -gt $cut -or $_.LastWriteTime -gt $cut) } |
                Select-Object -First $left)
        }
        if ($found.Count -gt $cap) {
            $script:Stat.trunc = $true
            $found = $found[0..($cap - 1)]
            "TRUNCATED: only the first $cap matching files are listed."
        }
        $script:Stat.files = $found.Count
        Fmt ($found | Select-Object FullName, Length, CreationTime, LastWriteTime)
    }
    $procs = Section 'Processes started in last 30 min' {
        $pc = (Get-Date).AddMinutes(-30)
        $rows = @(Get-CimInstance Win32_Process | Where-Object { $_.CreationDate -gt $pc })
        $script:Stat.procs = $rows.Count
        Fmt ($rows | Select-Object Name, ProcessId, ExecutablePath, CreationDate)
    }
    $note = ''; if ($script:Stat.trunc) { $note = ' (file list truncated at 5000)' }
    Res 'ok' "$($script:Stat.files) recent files, $($script:Stat.procs) new processes$note" ($files + $NL + $procs)
}

function Check-Evidence {
    function Ev($k) { if ($script:Ev.ContainsKey($k)) { $script:Ev[$k] } else { 'n/a: source check did not complete' } }
    $si = Section 'systeminfo OS lines' { systeminfo 2>$null | Select-String '^OS ' | ForEach-Object { $_.Line } }
    $text = "== System (check 1)$NL$(Ev 'sys')$NL$NL== Firewall state and default policy (check 3)$NL$(Ev 'fw')$NL$NL" +
        "== Defender status and signature timestamp (check 4)$NL$(Ev 'def')$NL$NL== Last hotfix (check 5)$NL$(Ev 'hf')$NL$NL$si"
    Res 'ok' 'evidence screens collected' $text
}

# ---------- main ----------
$parentDir = Split-Path $OutDir -Parent
$script:NewParent = [bool]($parentDir -and -not (Test-Path $parentDir))
$script:NewOut = -not (Test-Path $OutDir)
try {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
} catch {
    Write-Warning "Cannot create output folder ${OutDir}: $($_.Exception.Message)"
    exit 0
}
if (-not $script:IsAdmin) { Write-Warning 'Not running elevated: some checks will be incomplete.' }
if ([Environment]::OSVersion.Version.Major -lt 10) { Write-Warning 'Windows 7/8 detected: many checks need Windows 10 cmdlets and will read n/a.' }

# Admin-only ACL (SIDs: Administrators, SYSTEM). Skipped when not elevated, or we would lock ourselves out.
if ($script:IsAdmin) {
    try {
        # Only folders this run created are locked; an existing folder (for example -OutDir C:\Users\Public) is left alone.
        $lock = @(); if ($script:NewOut) { $lock += $OutDir }; if ($script:NewParent) { $lock += $parentDir }
        foreach ($d in $lock) {
            icacls $d /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning "icacls failed on $d (exit $LASTEXITCODE); folder ACL left as is." }
        }
    } catch { Write-Warning "icacls failed: $($_.Exception.Message)" }
} else {
    Write-Warning 'Output folder ACL not restricted because the run is not elevated.'
}

$checks = @(
    @('01 system', '01-system.txt', 'Check-System'),
    @('02 accounts', '02-accounts.txt', 'Check-Accounts'),
    @('03 firewall', '03-firewall.txt', 'Check-Firewall'),
    @('04 defender', '04-defender.txt', 'Check-Defender'),
    @('05 updates', '05-updates.txt', 'Check-Updates'),
    @('06 network', '06-network.txt', 'Check-Network'),
    @('07 persistence', '07-persistence.txt', 'Check-Persistence'),
    @('08 protocols', '08-protocols.txt', 'Check-Protocols'),
    @('09 shares', '09-shares.txt', 'Check-Shares'),
    @('10 recent', '10-recent.txt', 'Check-Recent'),
    @('11 evidence', '11-evidence.txt', 'Check-Evidence')
)
foreach ($c in $checks) { Invoke-Check $c[0] $c[1] $c[2] }

if ($script:SecFail.Count) { Add-Result '12 sections' 'unknown' "$($script:SecFail.Count) section(s) failed and read n/a, so findings and -Compare are unreliable: $(@($script:SecFail) -join '; ')" }

# Summary: one code path for console and summary.txt
$tags = @{ ok = '[ok]'; finding = '[!!]'; unknown = '[??]' }
$colors = @{ ok = 'Green'; finding = 'Red'; unknown = 'Yellow' }
$sum = @("Baseline of $env:COMPUTERNAME at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
foreach ($r in $script:Results) { $sum += ('{0} {1,-14} {2}' -f $tags[$r.Status], $r.Name, $r.Detail) }
$sum += "Output: $OutDir"
try { Set-Content -Path (Join-Path $OutDir 'summary.txt') -Value $sum -Encoding UTF8 } catch { Write-Warning 'cannot write summary.txt' }

# hashes.txt covers every other file, so later edits are noticeable
try {
    Get-ChildItem -Path $OutDir -File | Where-Object { $_.Name -ne 'hashes.txt' } | Sort-Object Name | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash, $_.Name
    } | Set-Content -Path (Join-Path $OutDir 'hashes.txt') -Encoding UTF8
} catch { Write-Warning "cannot write hashes.txt: $($_.Exception.Message)" }

if (-not $Quiet) {
    Write-Host $sum[0]
    foreach ($r in $script:Results) {
        Write-Host ('{0} {1,-14} {2}' -f $tags[$r.Status], $r.Name, $r.Detail) -ForegroundColor $colors[$r.Status]
    }
    Write-Host $sum[-1]
}

# -Compare: lines added or removed since an earlier baseline (checks 2, 6, 7, 9). Printed even with -Quiet.
function Read-Norm($path, $stop) {
    $out = @('#')   # sentinel keeps Compare-Object from seeing an empty collection
    if (Test-Path $path) {
        foreach ($l in (Get-Content -Path $path)) {
            if ($stop -and $l.StartsWith($stop)) { break }
            $n = ($l -replace '\s+', ' ').Trim()
            if ($n -and $n -notmatch '^[- ]+$') { $out += $n }   # drop blanks and table rules; spacing is normalized
        }
    }
    $out
}

if ($Compare) {
    Write-Host ''
    if (-not (Test-Path $Compare)) {
        Write-Warning "Compare folder not found: $Compare"
    } else {
        Write-Host "Compare against $Compare"
        # stop markers skip volatile sections (logged-on sessions, established connections)
        $pairs = @(@('02-accounts.txt', '== Logged-on'), @('06-network.txt', '== Established'), @('07-persistence.txt', ''), @('09-shares.txt', ''))
        foreach ($p in $pairs) {
            try {
                $old = Read-Norm (Join-Path $Compare $p[0]) $p[1]
                $new = Read-Norm (Join-Path $OutDir $p[0]) $p[1]
                if (@($old + $new | Where-Object { $_ -like '*n/a:*' }).Count) { Write-Host "   WARNING: $($p[0]) has n/a lines in one of the two runs, so this diff is unreliable" -ForegroundColor Red }
                $diff = @(Compare-Object -ReferenceObject $old -DifferenceObject $new)
                $add = @($diff | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { $_.InputObject })
                $gone = @($diff | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject })
                Write-Host "-- $($p[0]): $($add.Count) added, $($gone.Count) removed line(s)"
                foreach ($a in $add) { Write-Host "   + $a" -ForegroundColor Yellow }
                foreach ($g in $gone) { Write-Host "   - $g" -ForegroundColor DarkYellow }
            } catch { Write-Host "-- $($p[0]): n/a: $($_.Exception.Message)" }
        }
    }
}

exit 0
