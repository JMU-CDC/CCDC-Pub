#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Guided', 'Audit', 'Apply')][string]$Mode = 'Guided',
    [string[]]$AllowedClientAddress = @('Any'),
    [ValidateRange(1, 65535)][int[]]$ScoredTcpPort = @(1433, 5985, 5986),
    [ValidateRange(1, 65535)][int[]]$ScoredUdpPort = @(1434),
    [string]$SqlInstanceName = 'MSSQLSERVER',
    [switch]$Defender,
    [switch]$ExportQuotientPasswords,
    [string]$RecoveryLocalAdminName,
    [string]$DatabaseBackupTarget,
    [string]$ReportRoot = "$env:ProgramData\CCDC\MSSQL"
)

$ErrorActionPreference = 'Stop'
$script:RunContext = $PSCmdlet
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:CanWriteReport = $false
$script:CreatedRecovery = $null
$script:FirewallServicesReady = $false

function Read-StepChoice {
    param([string]$Name)
    if ($Mode -eq 'Apply') { return $true }
    Write-Host "`nNEXT: $Name" -ForegroundColor Cyan
    while ($true) {
        $answer = Read-Host 'Press Enter to run this action, or type n and press Enter to skip'
        if ($null -eq $answer) { throw 'Interactive input is unavailable; run from a console.' }
        if ($answer -eq '') { return $true }
        if ($answer.Trim() -ieq 'n') { return $false }
        Write-Host 'Only an empty Enter runs the action. Type n to skip.' -ForegroundColor Yellow
    }
}

function Install-TimestampPrompt {
    param([string]$ProfilePath=$PROFILE.CurrentUserAllHosts)
    if ([string]::IsNullOrWhiteSpace($ProfilePath)) { throw 'The current-user PowerShell profile path is unavailable.' }
    $begin = '# BEGIN CCDC TIMESTAMP PROMPT'
    $end = '# END CCDC TIMESTAMP PROMPT'
    $block = @'
# BEGIN CCDC TIMESTAMP PROMPT
function global:prompt {
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')] | PS $(Get-Location)`n--> "
}
$env:PROMPT = '$D$S$T$H$H$H$S$B$S$P$_--$G'
# END CCDC TIMESTAMP PROMPT
'@
    $exists = Test-Path -LiteralPath $ProfilePath -PathType Leaf -ErrorAction Stop
    $content = ''
    $encoding = New-Object Text.UTF8Encoding($true)
    if ($exists) {
        $reader = New-Object IO.StreamReader($ProfilePath, (New-Object Text.UTF8Encoding($false,$true)), $true)
        try {
            try { $content = $reader.ReadToEnd(); $encoding = $reader.CurrentEncoding }
            catch [Text.DecoderFallbackException] {
                $reader.Dispose()
                $reader = New-Object IO.StreamReader($ProfilePath, [Text.Encoding]::Default, $true)
                $content = $reader.ReadToEnd()
                $encoding = $reader.CurrentEncoding
            }
        } finally { $reader.Dispose() }
    }
    $beginMatches = [regex]::Matches($content, '(?m)^' + [regex]::Escape($begin) + '\r?$')
    $endMatches = [regex]::Matches($content, '(?m)^' + [regex]::Escape($end) + '\r?$')
    if ($beginMatches.Count -ne $endMatches.Count -or $beginMatches.Count -gt 1) {
        throw 'Existing timestamp profile markers are incomplete or duplicated.'
    }
    if ($beginMatches.Count) {
        $start = $beginMatches[0].Index
        $finish = $endMatches[0].Index + $end.Length
        $updated = $content.Substring(0,$start) + $block + $content.Substring($finish)
    } else {
        $separator = if ($content -and !$content.EndsWith("`n")) { [Environment]::NewLine } else { '' }
        $updated = $content + $separator + $block + [Environment]::NewLine
    }
    $profileTokens = $null; $profileErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($updated, [ref]$profileTokens, [ref]$profileErrors)
    if ($profileErrors.Count) { throw 'Resulting PowerShell profile has syntax errors.' }
    if ($updated -cne $content) {
        $parent = Split-Path -Parent $ProfilePath
        if (!(Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        [IO.File]::WriteAllText($ProfilePath, $updated, $encoding)
    }
    & ([scriptblock]::Create($block))
}

function Invoke-Step {
    param([Alias('Name')][string]$StepName, [scriptblock]$Action,
        [ValidateSet('Completed','PendingRestart')][string]$CompletionStatus='Completed')
    $status = 'Skipped'
    $errorText = ''
    try {
        if (!$script:RunContext.ShouldProcess($StepName, 'Run hardening plan action')) {
            $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
        } elseif (Read-StepChoice $StepName) {
            & $Action | Out-Host
            $status = $CompletionStatus
        }
    } catch {
        $status = 'Failed'
        $errorText = $_.Exception.Message
    }
    $script:Results.Add([pscustomobject]@{ Step=$StepName; Status=$status; Error=$errorText })
    if ($status -eq 'Failed') { Write-Warning "$StepName FAILED: $errorText" }
    else { Write-Host "[$status] $StepName" }
    return ($status -eq 'Completed')
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Assert-MSSQLServer {
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($computer.DomainRole -in 4, 5) {
        throw 'This node is a Domain Controller. Run the DC-specific hardening plan on domain controllers.'
    }
    if ($computer.PartOfDomain -ne $true) {
        Write-Warning 'Server is NOT joined to an Active Directory domain. Domain auth and SPN features will be bypassed.'
    }
    $sqlServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MSSQL*' -or $_.Name -like 'SQLSERVER*' })
    if (!$sqlServices.Count) {
        throw 'No SQL Server instance services were detected on this operating system.'
    }
    Write-Host "MSSQL host validated. Domain: $($computer.Domain) | Node: $($env:COMPUTERNAME)" -ForegroundColor Green
}

function Invoke-SqlInternal {
    param([Parameter(Mandatory)][string]$Query)
    if (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue) {
        return Invoke-Sqlcmd -Query $Query -ServerInstance $env:COMPUTERNAME -ErrorAction Stop
    }
    $sqlcmd = (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue).Source
    if ($sqlcmd) {
        $out = & $sqlcmd -S $env:COMPUTERNAME -E -b -Q $Query 2>&1
        if ($LASTEXITCODE -ne 0) { throw "sqlcmd execution failed: $($out -join ' ')" }
        return $out
    }
    $connStr = "Server=$env:COMPUTERNAME;Database=master;Integrated Security=True;"
    $conn = New-Object System.Data.SqlClient.SqlConnection($connStr)
    try {
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
        $dataset = New-Object System.Data.DataSet
        [void]$adapter.Fill($dataset)
        return $dataset.Tables[0]
    } finally {
        $conn.Dispose()
    }
}

function Backup-AllDatabases {
    param([string]$BackupPath)
    if (!(Test-Path -LiteralPath $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    $query = "SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' AND name != 'tempdb';"
    $databases = Invoke-SqlInternal -Query $query
    foreach ($row in $databases) {
        $db = if ($row.name) { $row.name } else { $row[0] }
        $fileName = Join-Path $BackupPath ("$db-{0:yyyyMMdd-HHmmss}.bak" -f (Get-Date))
        Write-Host "Backing up database [$db] to $fileName..."
        $sql = "BACKUP DATABASE [$db] TO DISK = N'$fileName' WITH FORMAT, INIT, SKIP, NOREWIND, NOUNLOAD, STATS = 10;"
        Invoke-SqlInternal -Query $sql | Out-Null
        if (!(Test-Path -LiteralPath $fileName)) { throw "Verification failed: Backup file not found for [$db]." }
    }
}

function Harden-SqlEngineConfiguration {
    $commands = @(
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
        "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;",
        "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;",
        "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;",
        "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;",
        "EXEC sp_configure 'remote access', 0; RECONFIGURE;",
        "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;"
    )
    foreach ($cmd in $commands) {
        Invoke-SqlInternal -Query $cmd | Out-Null
    }
    Write-Host 'Surface area protocols disabled: xp_cmdshell, Ole Automation, CLR, AdHoc Queries.' -ForegroundColor Green
}

function Set-RegistryDword {
    param([string]$Description, [string]$Path, [string]$Name, [int]$Value,
        [ValidateSet('Completed','PendingRestart')][string]$CompletionStatus='Completed')
    Invoke-Step "$Description ($Name = $Value)" -CompletionStatus $CompletionStatus {
        if (!(Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        if ((Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name -ne $Value) {
            throw 'Registry readback did not match.'
        }
    } | Out-Null
}

function Start-FirewallServices {
    foreach ($serviceName in 'BFE','MpsSvc') {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
            Start-Service -Name $serviceName -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [timespan]::FromSeconds(15))
        }
    }
}

function Set-NativeFirewallAllowRule {
    param([string]$RuleName, [ValidateSet('TCP','UDP','ICMPv4')][string]$Protocol, [string[]]$Port, [string[]]$Address=@('Any'))
    $protocolNumber = @{TCP=6;UDP=17;ICMPv4=1}[$Protocol]
    $remoteAddresses = if ($Address -contains 'Any' -or $Address -contains '*') { '*' } else { $Address -join ',' }
    
    $existing = @(& "$env:SystemRoot\System32\netsh.exe" advfirewall firewall show rule name="$RuleName" 2>&1)
    $action = if ($LASTEXITCODE -eq 0) { 'set' } else { 'add' }
    
    $arguments = @('advfirewall','firewall',$action,'rule',"name=$RuleName")
    if ($action -eq 'set') { $arguments += 'new' }
    $arguments += @('dir=in','action=allow','enable=yes','profile=any','localip=any',
        "remoteip=$(if ($remoteAddresses -eq '*') { 'any' } else { $remoteAddresses })",'interfacetype=any',
        'description=CCDC MSSQL Service Inbound Access')
    
    if ($Protocol -eq 'ICMPv4') { $arguments += 'protocol=icmpv4:8,any' }
    else { $arguments += @("protocol=$Protocol","localport=$($Port -join ',')",'remoteport=any') }
    
    Invoke-Native "$env:SystemRoot\System32\netsh.exe" $arguments
}

function Set-NativeFirewallProfiles {
    param([ValidateSet('Enabled','DefaultPolicy','Logging')][string]$Setting)
    switch ($Setting) {
        Enabled { Invoke-Native netsh.exe @('advfirewall','set','allprofiles','state','on') }
        DefaultPolicy { Invoke-Native netsh.exe @('advfirewall','set','allprofiles','firewallpolicy','blockinbound,allowoutbound') }
        Logging {
            Invoke-Native netsh.exe @('advfirewall','set','allprofiles','logging','allowedconnections','enable')
            Invoke-Native netsh.exe @('advfirewall','set','allprofiles','logging','droppedconnections','enable')
            Invoke-Native netsh.exe @('advfirewall','set','allprofiles','logging','maxfilesize','32767')
        }
    }
}

# --- INITIALIZATION ---
Assert-MSSQLServer
$report = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmss')

Invoke-Step 'Persist timestamped PowerShell session prompt' { Install-TimestampPrompt } | Out-Null

$script:CanWriteReport = Invoke-Step "Create protected logging directory: $report" {
    New-Item -ItemType Directory -Path $report -Force | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $report -AclObject $acl
}

# --- STAGE 0: DATABASE & CONFIGURATION BACKUP ---
Write-Host "`n0. Discovery & Database Safeguards" -ForegroundColor Cyan
Invoke-Step 'Audit running SQL services, ports, and listeners' {
    Get-Service -Name '*SQL*' | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize | Out-Host
    Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 1433,1434,4022,5985,5986 | Format-Table LocalAddress,LocalPort,OwningProcess -AutoSize | Out-Host
} | Out-Null

Invoke-Step 'Trigger full native database backups (All Online DBs)' {
    $targetPath = if ($DatabaseBackupTarget) { $DatabaseBackupTarget } else { Join-Path $report 'DatabaseBackups' }
    Backup-AllDatabases -BackupPath $targetPath
} | Out-Null

# --- STAGE 1: SQL INSTANCE SECURITY & SURFACE AREA REDUCTION ---
Write-Host "`n1. MSSQL Engine Hardening" -ForegroundColor Cyan
Invoke-Step 'Harden SQL Server sp_configure options (xp_cmdshell, CLR, OLE, AdHoc)' {
    Harden-SqlEngineConfiguration
} | Out-Null

Invoke-Step 'Audit sysadmin members and database TRUSTWORTHY properties' {
    $saAudit = "SELECT p.name AS Grantee, p.type_desc, p.is_disabled FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE r.name = 'sysadmin';"
    $trustAudit = "SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;"
    Write-Host "--- SYSADMIN MEMBERS ---" -ForegroundColor Yellow
    Invoke-SqlInternal -Query $saAudit | Format-Table -AutoSize | Out-Host
    Write-Host "--- TRUSTWORTHY DATABASES (Risk of Privilege Escalation) ---" -ForegroundColor Yellow
    Invoke-SqlInternal -Query $trustAudit | Format-Table -AutoSize | Out-Host
} | Out-Null

Invoke-Step 'Audit SA account and SQL Server Authentication Mode' {
    $saCheck = "SELECT name, is_disabled, is_policy_checked, is_expiration_checked FROM sys.sql_logins WHERE name = 'sa';"
    Invoke-SqlInternal -Query $saCheck | Format-Table -AutoSize | Out-Host
    Write-Host 'Verify if Mixed Mode (SQL + Windows Auth) is mandatory for scoring. If not, switch to Windows Authentication only in SSMS.' -ForegroundColor Yellow
} | Out-Null

# --- STAGE 2: HOST OS & NETWORK ACCESS DEFENSE ---
Write-Host "`n2. OS Protection & Protocols" -ForegroundColor Cyan
Set-RegistryDword 'Disable SMBv1 Server' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 -CompletionStatus PendingRestart
Set-RegistryDword 'Require SMB Server Signing' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1 -CompletionStatus PendingRestart
Set-RegistryDword 'Disable LLMNR' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
Set-RegistryDword 'Require NTLMv2, block LM/NTLMv1' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
Set-RegistryDword 'Restrict Anonymous SAM Enumeration' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1
Set-RegistryDword 'Disable WDigest Plaintext Caching' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0

# --- STAGE 3: FIREWALL ENFORCEMENT ---
Write-Host "`n3. Scoped Firewall Isolation" -ForegroundColor Cyan
$script:FirewallServicesReady = Invoke-Step 'Verify BFE and MpsSvc running' { Start-FirewallServices }

$sqlFwReady = Invoke-Step "Allow inbound MSSQL (TCP 1433, UDP 1434) from configured scope" {
    Set-NativeFirewallAllowRule -RuleName 'CCDC-MSSQL-TCP1433' -Protocol TCP -Port @('1433') -Address $AllowedClientAddress
    Set-NativeFirewallAllowRule -RuleName 'CCDC-MSSQL-UDP1434' -Protocol UDP -Port @('1434') -Address $AllowedClientAddress
}

foreach ($port in $ScoredTcpPort) {
    Invoke-Step "Allow scored TCP port $port" {
        Set-NativeFirewallAllowRule -RuleName "CCDC-Scored-TCP-$port" -Protocol TCP -Port @("$port") -Address @('Any')
    } | Out-Null
}

Invoke-Step 'Allow ICMPv4 Echo for Scoring/Gateway checks' {
    Set-NativeFirewallAllowRule -RuleName 'CCDC-ICMPv4' -Protocol ICMPv4 -Address @('Any')
} | Out-Null

Invoke-Step 'Enforce Windows Firewall on all profiles with Block Inbound / Allow Outbound' {
    Set-NativeFirewallProfiles -Setting Enabled
    Set-NativeFirewallProfiles -Setting DefaultPolicy
    Set-NativeFirewallProfiles -Setting Logging
} | Out-Null

# --- STAGE 4: AUDITING & TRANSCRIPTION ---
Write-Host "`n4. Telemetry & Auditing" -ForegroundColor Cyan
Set-RegistryDword 'Use Advanced Audit Policy Subcategories' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
Invoke-Step 'Enable Success/Failure Auditing' {
    Invoke-Native auditpol.exe @('/set','/category:*','/success:enable','/failure:enable')
} | Out-Null
Set-RegistryDword 'Enable PowerShell Script Block Logging' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Set-RegistryDword 'Include command lines in process creation events' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1

$transDir = "C:\ProgramData\CCDC\MSSQL\Transcripts"
if (!(Test-Path $transDir)) { 
    New-Item -ItemType Directory -Path $transDir -Force | Out-Null 
    icacls $transDir /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
}
$transPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (!(Test-Path $transPath)) { New-Item -Path $transPath -Force | Out-Null }
New-ItemProperty -LiteralPath $transPath -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath $transPath -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath $transPath -Name "OutputDirectory" -Value $transDir -PropertyType String -Force | Out-Null

$modPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (!(Test-Path $modPath)) { New-Item -Path $modPath -Force | Out-Null }
New-ItemProperty -LiteralPath $modPath -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null
$modNames = "$modPath\ModuleNames"
if (!(Test-Path $modNames)) { New-Item -Path $modNames -Force | Out-Null }
New-ItemProperty -LiteralPath $modNames -Name "*" -Value "*" -PropertyType String -Force | Out-Null

wevtutil sl "Security" /ms:536870912 /rt:false /ab:true
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456 /rt:false /ab:true

# --- REPORTING ---
if ($script:CanWriteReport) {
    $script:Results | Export-Csv -LiteralPath (Join-Path $report 'results.csv') -NoTypeInformation
    Write-Host "`nHardening run complete. Telemetry saved to: $report" -ForegroundColor Green
}
$script:Results | Format-Table -AutoSize
