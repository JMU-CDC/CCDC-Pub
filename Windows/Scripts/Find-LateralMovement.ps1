#Requires -Version 5.1
<#
.SYNOPSIS
Search local Windows logs or exported EVTX files for the lateral movement notes' indicators.
.DESCRIPTION
Read-only triage. Does not enable auditing, change services, or remove anything.
Findings are investigation leads, not proof of compromise. Run elevated for Security logs.
.EXAMPLE
.\Find-LateralMovement.ps1 -Hours 24
.EXAMPLE
.\Find-LateralMovement.ps1 -EvtxPath C:\Evidence\*.evtx -Hours 168 -MaxEventsPerSource 0
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 87600)][int]$Hours = 24,
    [string[]]$EvtxPath,
    [ValidateRange(0, 2147483646)][int]$MaxEventsPerSource = 50000,
    [string]$OutputDirectory = (Join-Path (Get-Location) ('LateralMovement-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff')))
)

function ConvertFrom-LmEvent {
    param([Parameter(Mandatory)]$Event)
    $xmlText = $Event.ToXml()
    [xml]$xml = $xmlText
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        if ($null -ne $node -and $node.HasAttribute('Name')) {
            $data[$node.GetAttribute('Name')] = $node.InnerText
        }
    }
    [pscustomobject]@{
        Id = [int]$xml.SelectSingleNode('/*[local-name()="Event"]/*[local-name()="System"]/*[local-name()="EventID"]').InnerText
        Provider = [string]$xml.Event.System.Provider.Name
        Computer = [string]$xml.Event.System.Computer
        Channel = [string]$xml.Event.System.Channel
        RecordId = [string]$xml.Event.System.EventRecordID
        TimeUtc = [string]$xml.Event.System.TimeCreated.SystemTime
        Data = $data
        Xml = $xmlText
    }
}

function Get-LmMatch {
    param([Parameter(Mandatory)]$Event)
    $d = $Event.Data
    $isSysmon = $Event.Provider -eq 'Microsoft-Windows-Sysmon'
    $isSecurity = $Event.Provider -eq 'Microsoft-Windows-Security-Auditing'
    $isProcess = ($isSysmon -and $Event.Id -eq 1) -or ($isSecurity -and $Event.Id -eq 4688)
    if ($isProcess) {
        $image = if ($isSysmon) { $d.Image } else { $d.NewProcessName }
        $parent = if ($isSysmon) { $d.ParentImage } else { $d.ParentProcessName }
        $command = [string]$d.CommandLine
        $parentCommand = [string]$d.ParentCommandLine
        $text = "$command`n$parentCommand"
        $shell = $image -match '(?i)(^|\\)(cmd|powershell|pwsh|wscript|cscript)\.exe$'
        $loopbackShare = $text -match '(?i)\\\\(127\.0\.0\.1|localhost)\\(ADMIN\$|C\$)\\'
        if ($loopbackShare -and $text -match '>') {
            [pscustomobject]@{Rule='LoopbackShareOutput'; Priority='High'; Reason='Command output redirected to a loopback administrative share (Impacket/CME-style artifact).'}
        }
        if ($parent -match '(?i)\\wmiprvse\.exe$' -and $shell) {
            [pscustomobject]@{Rule='WMIExec'; Priority='Review'; Reason='WMI provider spawned a command interpreter; compare source logons and administrative activity.'}
        }
        if (($parent -match '(?i)\\mmc\.exe$' -and $shell) -or
            ($parent -match '(?i)\\explorer\.exe$' -and $shell -and $loopbackShare) -or
            ($command -match '(?i)SHCreateLocalServerRunDll.*c08afd90-f2a1-11d1-8455-00a0c91f3880')) {
            [pscustomobject]@{Rule='DCOMExec'; Priority='Review'; Reason='MMC shell child, Explorer shell with loopback output, or the ShellBrowserWindow COM activation from the notes.'}
        }
        if ($shell -and ($parent -match '(?i)\\taskeng\.exe$' -or
            $parentCommand -match '(?i)svchost\.exe.*-s\s+Schedule\b')) {
            [pscustomobject]@{Rule='ScheduledTaskExec'; Priority='Review'; Reason='Task scheduler spawned an interpreter (AtExec-like); legitimate tasks can match.'}
        }
        if ($parent -match '(?i)\\services\.exe$' -and $shell) {
            [pscustomobject]@{Rule='ServiceShell'; Priority='High'; Reason='Service Control Manager directly spawned an interpreter (SMBExec/CME-like).'}
        }
        if ($text -match '(?i)\\(?:Windows\\)?Temp\\[^\s"<>|]+\.bat' -and
            ($loopbackShare -or ($text -match '(?i)\becho\b' -and $text -match '(?i)\bdel\b'))) {
            [pscustomobject]@{Rule='SMBExecBatch'; Priority='High'; Reason='Temporary batch execution with loopback-share output or echo/delete wrapper (SMBExec/CME-like).'}
        }
        if ("$image`n$parent`n$command" -match '(?i)(^|[\\\s"])(PSEXESVC|PAExec[^\\\s"]*|RemComSvc)\.exe\b') {
            [pscustomobject]@{Rule='PsExecArtifact'; Priority='Review'; Reason='Known PsExec/PAExec/RemCom service executable; authorized administration also matches.'}
        }
        if ($parent -match '(?i)\\services\.exe$' -and $image -match '(?i)^[a-z]:\\Windows\\[^\\]+\.exe$') {
            [pscustomobject]@{Rule='ServiceWindowsRootExecutable'; Priority='Review'; Reason='Service launched an executable directly under Windows (includes renamed Impacket service binaries).'}
        }
        if ($parent -match '(?i)\\wsmprovhost\.exe$') {
            [pscustomobject]@{Rule='WinRMChild'; Priority='Review'; Reason='WinRM host spawned a process; verify whether the remote administration was authorized.'}
        }
        if ($image -match '(?i)\\rdpclip\.exe$') {
            [pscustomobject]@{Rule='RDPProcess'; Priority='Context'; Reason='RDP clipboard process observed; indicates session activity, not maliciousness.'}
        }
        if ($text -match '(?i)handlekatz|tasklist[^\r\n]*lsass') {
            [pscustomobject]@{Rule='CredentialAccessIndicator'; Priority='High'; Reason='HandleKatz name or tasklist command referencing LSASS, as illustrated in the notes.'}
        }
    }
    # Commands may appear in process creation or PowerShell script block logging.
    if ($isProcess -or ($Event.Provider -eq 'Microsoft-Windows-PowerShell' -and $Event.Id -eq 4104)) {
        $text = if ($isProcess) { [string]$d.CommandLine } else { [string]$d.ScriptBlockText }
        if ($text -match '(?i)Enable-PSRemoting|\bwinrm(?:\.exe)?\s+(quickconfig|qc)\b') {
            [pscustomobject]@{Rule='WinRMEnableCommand'; Priority='Review'; Reason='Command referencing WinRM/remoting enablement; verify execution and authorization.'}
        }
        if ($text -match '(?i)fDenyTSConnections' -or
            $text -match '(?i)Enable-NetFirewallRule[^\r\n]*Remote Desktop' -or
            $text -match '(?i)netsh[^\r\n]*(remotedesktop|localport\s*=\s*3389)') {
            [pscustomobject]@{Rule='RDPConfigurationCommand'; Priority='Review'; Reason='Command referencing RDP access settings; inspect arguments to determine whether access was enabled or disabled.'}
        }
    }
    if ($isSysmon -and $Event.Id -eq 11 -and $d.TargetFilename -match '(?i)\\(PSEXESVC|PAExec[^\\]*|RemComSvc|handlekatz)\.exe$') {
        [pscustomobject]@{Rule='ToolFileCreated'; Priority='Review'; Reason='File creation matching a service tool or HandleKatz filename from the notes.'}
    }
    if ($isSysmon -and $Event.Id -eq 13 -and
        $d.TargetObject -match '(?i)\\Terminal Server\\fDenyTSConnections$' -and
        $d.Details -match '(?i)DWORD\s*\(0x0{8}\)') {
        [pscustomobject]@{Rule='RDPEnabledRegistry'; Priority='Review'; Reason='RDP deny-connections value set to zero; verify authorized change.'}
    }
    if ($isSecurity -and $Event.Id -eq 4624 -and $d.LogonType -eq '10') {
        [pscustomobject]@{Rule='RDPLogon'; Priority='Context'; Reason='Successful RemoteInteractive logon; correlate account and source IP with approved access.'}
    }
    if ($Event.Provider -eq 'Service Control Manager' -and $Event.Id -eq 7045) {
        $binary = [string]$d.ImagePath
        if ("$($d.ServiceName) $binary" -match '(?i)psexesvc|paexec|remcom|\\Windows\\[^\\"\s]+\.exe\b|\bcmd(?:\.exe)?\b|powershell|\\Temp\\') {
            [pscustomobject]@{Rule='SuspiciousServiceInstall'; Priority='Review'; Reason='Installed service uses a tool name, interpreter, Windows-root executable, or temporary path.'}
        }
    }
}

# Dot-source for rule testing without querying logs or writing reports.
if ($MyInvocation.InvocationName -eq '.') { return }
$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-$Hours)
$end = Get-Date
$findings = New-Object 'System.Collections.Generic.List[object]'
$coverage = New-Object 'System.Collections.Generic.List[object]'
$sources = @()
if ($EvtxPath) {
    foreach ($pattern in $EvtxPath) {
        foreach ($file in (Resolve-Path -Path $pattern -ErrorAction Stop)) {
            $sources += @{ Path = $file.ProviderPath; Id = @(1,11,13,4688,4624,7045,4104) }
        }
    }
    if ($sources.Count -eq 0) { throw 'No EVTX files matched EvtxPath.' }
} else {
    $sources = @(
        @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = @(1,11,13) },
        @{ LogName = 'Security'; Id = @(4688,4624) },
        @{ LogName = 'System'; Id = @(7045) },
        @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = @(4104) }
    )
}
foreach ($source in $sources) {
    $label = if ($source.Path) { $source.Path } else { $source.LogName }
    Write-Host "Scanning $label ..." -ForegroundColor Cyan
    $filter = $source.Clone()
    $filter.StartTime = $start
    $filter.EndTime = $end
    $query = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
    if ($MaxEventsPerSource -gt 0) { $query.MaxEvents = $MaxEventsPerSource + 1 }
    $state = [pscustomobject]@{ Source=$label; Status='Scanned'; EventsRead=0; ParseErrors=0; EventCounts=@{}; Error='' }
    try {
        Get-WinEvent @query | ForEach-Object {
            if ($MaxEventsPerSource -gt 0 -and $state.EventsRead -ge $MaxEventsPerSource) {
                $state.Status = 'Truncated'
            } else {
                $state.EventsRead++
                try {
                    $event = ConvertFrom-LmEvent $_
                    $key = '{0}/{1}' -f $event.Provider, $event.Id
                    $state.EventCounts[$key] = 1 + [int]$state.EventCounts[$key]
                    foreach ($match in @(Get-LmMatch $event)) {
                        $d = $event.Data
                        $findings.Add([pscustomobject]@{
                            TimeUtc=$event.TimeUtc; Computer=$event.Computer; Rule=$match.Rule
                            Priority=$match.Priority; Reason=$match.Reason; Channel=$event.Channel
                            EventId=$event.Id; RecordId=$event.RecordId; Source=$label
                            User=(@($d.User,$d.TargetUserName,$d.SubjectUserName) | Where-Object { $_ } | Select-Object -First 1)
                            SourceIP=$d.IpAddress; Image=(@($d.Image,$d.NewProcessName,$d.ImagePath) | Where-Object { $_ } | Select-Object -First 1)
                            ParentImage=(@($d.ParentImage,$d.ParentProcessName) | Where-Object { $_ } | Select-Object -First 1)
                            CommandLine=$d.CommandLine; ParentCommandLine=$d.ParentCommandLine
                            ProcessGuid=$d.ProcessGuid; ParentProcessGuid=$d.ParentProcessGuid
                            Data=$d; EventXml=$event.Xml
                        })
                    }
                } catch {
                    $state.ParseErrors++
                    $state.Error = $_.Exception.Message
                }
            }
        }
        if ($state.ParseErrors -gt 0 -and $state.Status -ne 'Truncated') { $state.Status = 'Partial' }
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $state.Status = 'NoEvents' }
        else { $state.Status = 'Failed'; $state.Error = $_.Exception.Message }
    }
    $coverage.Add($state)
    if ($state.Status -in @('Failed','Partial','Truncated')) {
        Write-Warning "$label : $($state.Status). $($state.Error) Check coverage.json; rerun capped scans with -MaxEventsPerSource 0."
    }
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$ordered = @($findings | Sort-Object TimeUtc, Computer, RecordId, Rule)
ConvertTo-Json -InputObject $ordered -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'findings.json') -Encoding UTF8
if ($ordered.Count -gt 0) {
    $ordered | Select-Object * -ExcludeProperty Data,EventXml | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'findings.csv') -NoTypeInformation -Encoding UTF8
} else {
    '"TimeUtc","Computer","Rule","Priority","Reason","Channel","EventId","RecordId","Source","User","SourceIP","Image","ParentImage","CommandLine","ParentCommandLine","ProcessGuid","ParentProcessGuid"' |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'findings.csv') -Encoding UTF8
}
$report = [pscustomobject]@{
    StartTimeUtc=$start.ToUniversalTime().ToString('o'); EndTimeUtc=$end.ToUniversalTime().ToString('o')
    MaxEventsPerSource=$MaxEventsPerSource; FindingCount=$ordered.Count; Sources=@($coverage.ToArray())
    Limitations='Heuristic leads only. Missing, filtered, cleared, or overwritten telemetry cannot be recovered. No matches does not establish a clean host. Newest events are scanned first; a capped scan omits older events.'
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'coverage.json') -Encoding UTF8
$coverage | Select-Object Source,Status,EventsRead,ParseErrors | Format-Table -AutoSize | Out-Host
$ordered | Group-Object Priority,Rule | Select-Object Count,Name | Format-Table -AutoSize | Out-Host
Write-Host "$($ordered.Count) findings. Reports: $OutputDirectory"
Write-Host 'Review coverage.json before interpreting results. Matches can be legitimate administration; no matches does not establish a clean host.'
