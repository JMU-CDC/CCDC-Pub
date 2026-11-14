<#
.SYNOPSIS
  Read-only "did I break anything" check for the Windows 11 competition workstation that also runs the Velociraptor server.
.DESCRIPTION
  Windows 11 edition of Test-WorkstationHealth.ps1 (see Win11-Scripts.SPEC.md): adds a Velociraptor section.
  Implements Test-WorkstationHealth.SPEC.md. Windows PowerShell 5.1. Changes nothing, installs
  nothing, contains no secrets, scans nothing: it only reads local state, pings the local
  gateway, asks the machine's own DNS servers a question, and makes one TCP connect to -InternetHost.
  Run it before hardening, after hardening, and after any network isolation is lifted, then compare.
  Written after the Nov 7 2026 event, where the workstation lost internet after the five-minute plan.
.PARAMETER Names
  Names that must resolve through each configured DNS server. Defaults to the domain name when joined.
.PARAMETER Reach
  Internal targets that must accept a TCP connection, as host:port, for example 172.20.240.200:443
  (the Palo Alto web page). One connect each with a 3 second timeout; never scans.
.PARAMETER InternetExpected
  Competition boxes are air-gapped, so the outbound internet test is skipped by default. Give this
  switch on a box that should reach the internet (practice VM): a failure is then a FAIL.
.PARAMETER InternetHost
  Host for the outbound 443 test when -InternetExpected is given.
.PARAMETER Velociraptor
  Velociraptor server is meant to be running on this box: a missing listener on the frontend port or GUI port is then a FAIL.
  Without it the Velociraptor section only reports what it finds, except an exposed GUI or an open listener with no firewall rule, which always FAIL.
.PARAMETER VeloFrontendPort
  Client (frontend) port, default 8000.
.PARAMETER VeloGuiPort
  GUI port, default 8889.
#>
param(
    [string[]]$Names = @(),
    [string[]]$Reach = @(),
    [switch]$InternetExpected,
    [string]$InternetHost = 'github.com',
    [switch]$Velociraptor,
    [int]$VeloFrontendPort = 8000,
    [int]$VeloGuiPort = 8889,
    [int]$VeloFilePort = 8080
)

# Constrained Language Mode (Smart App Control or an application-control policy) breaks the New-Object calls below. Stop with a clear message.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw "PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode (Smart App Control or an application-control policy is on). This script needs FullLanguage. Do not run it; tell the team."
}

$ErrorActionPreference = 'SilentlyContinue'   # every check handles its own failure and prints a line
$script:NFail = 0   # PowerShell variable names are case-insensitive: never name another variable $bad
function Ok($m)   { Write-Host "  [PASS] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:NFail++ }
function Info($m) { Write-Host "  [info] $m" -ForegroundColor Gray }
function Warn($m) { Write-Host "  [warn] $m" -ForegroundColor Yellow }
function Hdr($m)  { Write-Host "== $m" -ForegroundColor Cyan }

if ([Environment]::OSVersion.Version.Major -lt 10) {
    Write-Host 'Windows 7/8: the network and firewall cmdlets this check uses do not exist, so it cannot run. Use: ipconfig /all, ping <gateway>, nslookup <dc>, netsh advfirewall show allprofiles' -ForegroundColor Yellow
    exit 2
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

Hdr 'host'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Info "$($os.Caption) build $($os.BuildNumber), host $($cs.Name), user $env:USERNAME, $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Warn 'not elevated: the secure-channel and firewall checks are skipped or may be incomplete' }
$downAdapters = @(Get-NetAdapter | Where-Object { $_.Status -ne 'Up' -and $_.HardwareInterface })
foreach ($a in $downAdapters) { Warn "adapter $($a.Name) is $($a.Status)" }

Hdr 'network profile (Nov 7: the Public profile was active)'
$active = @()
foreach ($p in @(Get-NetConnectionProfile)) {
    $fw = if ("$($p.NetworkCategory)" -eq 'DomainAuthenticated') { 'Domain' } else { "$($p.NetworkCategory)" }
    $active += $fw
    $m = "$($p.InterfaceAlias): $($p.NetworkCategory) profile, IPv4 $($p.IPv4Connectivity)"
    if ($cs.PartOfDomain -and $fw -ne 'Domain') { Bad "$m. Domain-joined but not on the Domain profile: the domain controller is unreachable or DNS is wrong, and the stricter Public rules apply" }
    else { Info $m }
}
$active = @($active | Select-Object -Unique)

Hdr 'domain'
if ($cs.PartOfDomain) {
    Info "domain joined: $($cs.Domain)"
    if ($Names.Count -eq 0) { $Names = @($cs.Domain) }
    if (-not $admin) { Warn 'secure channel skipped (needs elevation)' }
    else {
        try {
            if (Test-ComputerSecureChannel -ErrorAction Stop) { Ok 'secure channel to the domain controller is healthy' }
            else { Bad 'secure channel failed OR the domain controller is unreachable: check DNS and reachability before blaming the trust' }
        } catch { Warn "secure channel not tested: $($_.Exception.Message)" }
    }
} else { Info 'standalone (not domain joined)' }

Hdr 'network'
$cfg = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway })
if (-not $cfg) { Bad 'no interface has a default gateway' }
foreach ($c in $cfg) {
    $dns = @($c.DNSServer.ServerAddresses | Where-Object { $_ -notmatch ':' })
    $ip = $c.IPv4Address.IPAddress
    Info "$($c.InterfaceAlias): ip $ip, dns $($dns -join ',')"
    $addr = @(Get-NetIPAddress -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4)
    foreach ($a in $addr) {
        if ($a.IPAddress -like '169.254.*') { Bad "$($a.IPAddress) is an APIPA address: DHCP failed" }
        elseif ($a.PrefixOrigin -eq 'Manual') { Warn "$($a.IPAddress) is a static address; packet p17 rule 7 forbids changing IPs without an inject" }
    }
    foreach ($g in @($c.IPv4DefaultGateway)) {
        $gw = $g.NextHop
        if (Test-Connection -ComputerName $gw -Count 2 -Quiet) { Ok "gateway $gw answers ping" }
        else {
            $nb = (Get-NetNeighbor -IPAddress $gw).State
            Warn "gateway $gw does not answer ping (neighbor state: $nb; Incomplete or Unreachable means a link problem, Reachable or Stale means ping is probably dropped by policy)"
        }
    }
    if (-not $dns) { Bad "$($c.InterfaceAlias) has no IPv4 DNS server" }
    foreach ($s in $dns) {
        if ($s -eq '127.0.0.1' -or $s -eq $ip) { Warn "DNS server $s is this machine itself: fine on a domain controller, wrong on a workstation" }
        foreach ($n in $Names) {
            $r = Resolve-DnsName $n -Server $s -DnsOnly -QuickTimeout -Type A | Where-Object { $_.IPAddress } | Select-Object -First 1
            if ($r) { Ok "DNS server $s resolves $n -> $($r.IPAddress)" } else { Bad "DNS server $s cannot resolve $n" }
        }
    }
}
if ($InternetExpected) {
    $ipx = (Resolve-DnsName $InternetHost -DnsOnly -QuickTimeout -Type A | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
    $up = $false
    if ($ipx) {
        $tc = New-Object Net.Sockets.TcpClient
        $iar = $tc.BeginConnect($ipx, 443, $null, $null)
        $up = $iar.AsyncWaitHandle.WaitOne(3000) -and $tc.Connected
        $tc.Close()
    }
    if ($up) { Ok "outbound 443 to $InternetHost ($ipx) works" }
    elseif (-not $ipx) { Bad "cannot resolve ${InternetHost}: DNS or routing is down" }
    else { Bad "outbound 443 to $InternetHost ($ipx) fails: check the outbound firewall lines and the gateway" }
} else { Info 'outbound internet test skipped (competition boxes are air-gapped); use -InternetExpected on a box that should reach the internet' }
foreach ($t in $Reach) {
    $hp = $t -split ':'
    if ($hp.Count -ne 2 -or $hp[1] -notmatch '^\d+$') { Bad "-Reach '$t' is not host:port"; continue }
    $tc = New-Object Net.Sockets.TcpClient
    $iar = $tc.BeginConnect($hp[0], [int]$hp[1], $null, $null)
    $up = $iar.AsyncWaitHandle.WaitOne(3000) -and $tc.Connected
    $tc.Close()
    if ($up) { Ok "$t accepts connections" } else { Bad "$t does not accept connections" }
}
$px = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($px.ProxyEnable -eq 1 -or $px.AutoConfigURL) { Warn "user proxy set: $($px.ProxyServer) $($px.AutoConfigURL)" }
foreach ($l in @(netsh winhttp show proxy)) { if ($l -match '^\s*Proxy Server\(s\)') { Warn "winhttp: $($l.Trim())" } }
foreach ($l in @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -match '^\s*[^#\s]' })) { Warn "hosts file entry: $($l.Trim())" }
foreach ($svc in @(Get-Service Dnscache, Dhcp, NlaSvc, netprofm, Netlogon, W32Time, BFE, MpsSvc | Where-Object { $_.Status -ne 'Running' })) {
    if ($svc.Name -eq 'Netlogon' -and -not $cs.PartOfDomain) { continue }
    Warn "service $($svc.Name) is $($svc.Status)"
}

Hdr 'firewall'
Get-EffProfiles | ForEach-Object {
    Info "$($_.Name): enabled=$($_.Enabled) in=$($_.DefaultInboundAction) out=$($_.DefaultOutboundAction) allowInboundRules=$($_.AllowInboundRules)"
    if ($_.Enabled -eq 'True' -and $_.DefaultOutboundAction -eq 'Block') { Bad "$($_.Name): default OUTBOUND is Block, a likely cause of lost internet" }
    if ($_.AllowInboundRules -eq 'False') { Bad "$($_.Name): 'block all incoming' is on, so no allow rule (including ping) works" }
}
foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Block -Enabled True)) { Warn "outbound block rule active: $($r.DisplayName)" }
try {
    $echoOk = @(); $echoBlock = @()
    # Load every port and address filter once; asking per rule is slow with a few hundred rules.
    $pfAll = @{}; foreach ($f in @(Get-NetFirewallPortFilter -PolicyStore ActiveStore)) { $pfAll[$f.InstanceID] = $f }
    $afAll = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore)) { $afAll[$f.InstanceID] = $f }
    foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -ErrorAction Stop)) {
        $pf = $pfAll[$r.Name]; if (-not $pf) { $pf = $r | Get-NetFirewallPortFilter }
        if (@($pf.Protocol) -notcontains 'ICMPv4' -and @($pf.Protocol) -notcontains '1') { continue }
        $types = @($pf.IcmpType)
        if (-not ($types -contains '8' -or $types -contains 'Any' -or $types.Count -eq 0)) { continue }   # not echo request
        $rp = "$($r.Profile)"
        if ($active.Count -and $rp -ne 'Any' -and -not ($active | Where-Object { $rp -match $_ })) { continue }   # not for the active profile
        $af = $afAll[$r.Name]; if (-not $af) { $af = $r | Get-NetFirewallAddressFilter }
        $remote = @($af.RemoteAddress)
        $anyRemote = ($remote -contains 'Any')
        if ($r.Action -eq 'Allow' -and $anyRemote) { $echoOk += $r }
        elseif ($r.Action -eq 'Block' -and $anyRemote) { $echoBlock += $r }
        elseif ($r.Action -eq 'Block') { Info "single-source ICMP block rule: $($r.DisplayName) ($($remote -join ','))" }
        elseif ($r.Action -eq 'Allow') { Info "ICMP allow limited to $($remote -join ','): $($r.DisplayName) (does not count, packet p17 rule 9 wants all sources)" }
    }
    if ($echoBlock) { Bad "enabled inbound ICMP BLOCK rule for all sources: $(@($echoBlock.DisplayName) -join '; ')" }
    if ($echoOk) { Ok "inbound ping allowed from all sources on the active profile ($(@($echoOk.DisplayName)[0]))" }
    else { Bad 'no enabled inbound echo-request allow rule for all sources on the active profile: ping will not be answered (packet p19 rule 12)' }
} catch {
    if ($admin) { Bad "could not read firewall rules: $($_.Exception.Message)" } else { Warn 'firewall rules not read (not elevated)' }
}

Hdr "velociraptor (clients need inbound $VeloFrontendPort, GUI $VeloGuiPort should be localhost only)"
$frontL = @(Get-NetTCPConnection -State Listen -LocalPort $VeloFrontendPort)
$guiL = @(Get-NetTCPConnection -State Listen -LocalPort $VeloGuiPort)
$fids = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore | Where-Object { @($_.LocalPort) -contains "$VeloFrontendPort" -and "$($_.Protocol)" -in 'TCP', '6' } | ForEach-Object { $_.InstanceID })
$fids += @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore | Where-Object { "$($_.Program)" -like '*velociraptor*' } | ForEach-Object { $_.InstanceID })   # program rule from the "Allow access" pop-up
$fallow = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow | Where-Object { $fids -contains $_.Name })
if ($frontL.Count) {
    Ok "frontend port $VeloFrontendPort is listening on $((@($frontL.LocalAddress) | Sort-Object -Unique) -join ', ')"
    $tc = New-Object Net.Sockets.TcpClient
    $iar = $tc.BeginConnect('127.0.0.1', $VeloFrontendPort, $null, $null)
    $up = $iar.AsyncWaitHandle.WaitOne(3000) -and $tc.Connected
    $tc.Close()
    if ($up) { Ok "local connect to 127.0.0.1:$VeloFrontendPort works" } else { Warn "frontend listens but 127.0.0.1:$VeloFrontendPort refused a connect (bound to one address only?)" }
} elseif ($Velociraptor) { Bad "nothing is listening on frontend port ${VeloFrontendPort}: the Velociraptor server is not running or uses another port" }
else { Info "nothing is listening on frontend port $VeloFrontendPort (use -Velociraptor once the server should be up)" }
if ($fallow.Count) { Ok "inbound allow rule for TCP $VeloFrontendPort exists: $(@($fallow.DisplayName) -join '; ')" }
elseif ($frontL.Count -or $Velociraptor) { Bad "no enabled inbound allow rule for TCP ${VeloFrontendPort}: clients on other machines cannot enrol (the hardener's velo step adds one)" }
else { Info "no inbound allow rule for TCP $VeloFrontendPort yet" }
if ($guiL.Count) {
    $ga = @($guiL.LocalAddress | Sort-Object -Unique)
    if (@($ga | Where-Object { $_ -notin '127.0.0.1', '::1' }).Count) { Bad "GUI port $VeloGuiPort listens on $($ga -join ', '), not localhost only: the console is reachable from the network" }
    else { Ok "GUI port $VeloGuiPort listens on localhost only ($($ga -join ', '))" }
} elseif ($Velociraptor) { Bad "nothing is listening on GUI port $VeloGuiPort" }
else { Info "nothing is listening on GUI port $VeloGuiPort" }

if ($VeloFilePort) {
    $fpIds = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore | Where-Object { @($_.LocalPort) -contains "$VeloFilePort" -and "$($_.Protocol)" -in 'TCP', '6' } | ForEach-Object { $_.InstanceID })
    $fpAllow = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow | Where-Object { $fpIds -contains $_.Name })
    $fpL = @(Get-NetTCPConnection -State Listen -LocalPort $VeloFilePort)
    Info "client-file port ${VeloFilePort} (python -m http.server): listening=$([bool]$fpL.Count) allowRule=$(if ($fpAllow.Count) { @($fpAllow.DisplayName) -join '; ' } else { 'none' })"
    if ($fpL.Count -and -not $fpAllow.Count) { Warn "something listens on $VeloFilePort but no inbound allow rule exists: other boxes cannot download the client files" }
}

Hdr 'protection'
$d = Get-MpComputerStatus
if ($d) {
    if ($d.RealTimeProtectionEnabled) { Ok 'Defender real-time protection on' }
    else { Bad 'Defender real-time protection off (check whether another antivirus has put Defender in passive mode)' }
    Info "signatures updated $($d.AntivirusSignatureLastUpdated)"
} else { Warn 'Defender status unavailable' }

Hdr 'time and remote access (left as found on purpose, White/Green Team may need access)'
$tl = @(w32tm /query /status | Where-Object { $_ -match 'Source|Last Successful Sync' })
foreach ($l in $tl) { Info "time: $($l.Trim())" }
$rdpOff = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
Info "RDP enabled: $($rdpOff -eq 0)"
$wr = Get-Service WinRM
Info "WinRM service: $(if ($wr) { $wr.Status } else { 'absent' })"
$la = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
Info ('local admins: ' + $(if ($la) { (@($la.Name) -join ', ') } else { 'unavailable (domain controller unreachable or lookup error)' }))

if ($script:NFail) { Write-Host "`n$script:NFail problem(s), read the [FAIL] lines." -ForegroundColor Red; exit 1 }
Write-Host "`nNo failures." -ForegroundColor Green
