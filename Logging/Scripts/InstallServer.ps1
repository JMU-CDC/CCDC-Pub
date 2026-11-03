<#
.SYNOPSIS
  Installs and hardens a Velociraptor server on Windows.


    #thanksgpt6.1sol


.EXAMPLE
  .\Install-VelociraptorServer.ps1 -ServerName 172.20.240.50 -AllowedSubnets 172.20.240.0/24

.NOTES
  Run from an elevated PowerShell prompt. Needs internet access to github.com
  (or use -ExePath to supply a binary you already downloaded).
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Hostname or IP that CLIENTS will use to reach this server. Must be stable.
    [string]$ServerName = $env:COMPUTERNAME,

    # Networks allowed to reach the client frontend (port 8000).
    [string[]]$AllowedSubnets = @('172.20.240.0/24'),

    [int]$FrontendPort = 8000,

    [string]$InstallDir = "$env:ProgramFiles\Velociraptor",
    [string]$DataRoot   = "$env:ProgramData\Velociraptor",

    # Optional: use a binary you already have instead of downloading.
    [string]$ExePath,

    # Optional: a Velociraptor .msi (if omitted, one next to this script is auto-detected).
    [string]$MsiPath,

    # Disable the execve() plugin on endpoints (blocks shell commands pushed from the server).
    [bool]$PreventExecve = $true,

    # Run the server as NT AUTHORITY\LOCAL SERVICE instead of SYSTEM (falls back to SYSTEM if it fails).
    [bool]$RunAsLocalService = $true
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Utf8NoBom($Path, $Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
}
function Lock-Path([string]$Path, [string[]]$ExtraGrants = @()) {
    # SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) only, plus any extras
    $args = @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '/grant:r', '*S-1-5-32-544:(OI)(CI)F')
    foreach ($g in $ExtraGrants) { $args += @('/grant:r', $g) }
    & icacls.exe @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

# ------------------------------------------------------------------ 1. Binary
Write-Step 'Preparing directories'
$Datastore = Join-Path $DataRoot 'datastore'
$LogDir    = Join-Path $DataRoot 'logs'
$ServerCfg = Join-Path $DataRoot 'server.config.yaml'
$ClientCfg = Join-Path $DataRoot 'client.config.yaml'
foreach ($d in $InstallDir, $DataRoot, $Datastore, $LogDir) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
Lock-Path $DataRoot   # lock down before any secrets are written

$Exe = Join-Path $InstallDir 'velociraptor.exe'

# An earlier install (e.g. running the MSI normally) leaves a service holding the exe open.
if (Get-Service Velociraptor -ErrorAction SilentlyContinue) {
    Write-Step 'Existing Velociraptor service found: stopping and removing it'
    Stop-Service Velociraptor -Force -ErrorAction SilentlyContinue
    & sc.exe delete Velociraptor | Out-Null
}
Unregister-ScheduledTask -TaskName 'Velociraptor Server' -Confirm:$false -ErrorAction SilentlyContinue
Get-Process -Name velociraptor -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

if (-not $ExePath -and -not $MsiPath -and $PSScriptRoot) {
    $found = Get-ChildItem $PSScriptRoot -Filter 'velociraptor*.msi' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $MsiPath = $found.FullName }
}

if ($ExePath) {
    Write-Step "Using supplied binary $ExePath"
    Copy-Item $ExePath $Exe -Force
} elseif ($MsiPath) {
    Write-Step "Extracting binary from $MsiPath (no install, extract only)"
    $tmp = Join-Path $env:TEMP "velo_msi_$(Get-Random)"
    $p = Start-Process msiexec.exe -ArgumentList "/a `"$MsiPath`" /qn TARGETDIR=`"$tmp`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec extract failed with exit code $($p.ExitCode)" }
    $extracted = Get-ChildItem $tmp -Recurse -Filter 'velociraptor*.exe' | Select-Object -First 1
    if (-not $extracted) { throw 'No velociraptor .exe found inside the MSI.' }
    Copy-Item $extracted.FullName $Exe -Force
    Remove-Item $tmp -Recurse -Force
} else {
    Write-Step 'Finding latest Velociraptor release'
    $rel   = Invoke-RestMethod 'https://api.github.com/repos/Velocidex/velociraptor/releases/latest' `
             -Headers @{ 'User-Agent' = 'ccdc-install-script' }
    $asset = $rel.assets | Where-Object { $_.name -match 'windows-amd64\.exe$' } | Select-Object -First 1
    if (-not $asset) { throw 'Could not find a windows-amd64 .exe asset in the latest release.' }
    Write-Host "Release $($rel.tag_name): $($asset.name)"
    Invoke-WebRequest $asset.browser_download_url -OutFile $Exe -UseBasicParsing
}

$sig = Get-AuthenticodeSignature $Exe
Write-Host "SHA256:    $((Get-FileHash $Exe -Algorithm SHA256).Hash)"
Write-Host "Signature: $($sig.Status) $($sig.SignerCertificate.Subject)"
if ($sig.Status -ne 'Valid') {
    Write-Warning 'Binary is not validly signed. Verify the hash against the GitHub release before continuing.'
    if ((Read-Host 'Continue anyway? (y/N)') -ne 'y') { exit 1 }
}
& $Exe version

# ------------------------------------------------------------------ 2. Config
Write-Step 'Generating server config'
$merge = @{
    Client = @{
        server_urls    = @("https://${ServerName}:$FrontendPort/")
        prevent_execve = $PreventExecve
    }
    Frontend   = @{ hostname = $ServerName; bind_address = '0.0.0.0'; bind_port = $FrontendPort }
    GUI        = @{ bind_address = '127.0.0.1' }
    API        = @{ bind_address = '127.0.0.1' }
    Monitoring = @{ bind_address = '127.0.0.1' }
    Datastore  = @{ location = $Datastore; filestore_directory = $Datastore }
    Logging    = @{ output_directory = $LogDir; separate_logs_per_component = $true }
}
$mergeFile = Join-Path $DataRoot 'merge.json'
Write-Utf8NoBom $mergeFile ($merge | ConvertTo-Json -Depth 6)

$cfgText = & $Exe config generate --merge_file $mergeFile
if ($LASTEXITCODE -ne 0 -or -not $cfgText) { throw 'config generate failed' }
Write-Utf8NoBom $ServerCfg ($cfgText -join "`n")
Remove-Item $mergeFile -Force

if (-not (Select-String -Path $ServerCfg -Pattern ([regex]::Escape($ServerName)) -Quiet)) {
    throw "Merged settings did not apply (server name not found in config). Check the Velociraptor version."
}

Write-Step 'Generating client config'
$clientText = & $Exe --config $ServerCfg config client
if ($LASTEXITCODE -ne 0 -or -not $clientText) { throw 'config client failed' }
Write-Utf8NoBom $ClientCfg ($clientText -join "`n")

# ------------------------------------------------------------------ 3. Admin user
Write-Step 'Create the Velociraptor GUI user'
do {
    $GuiUser = (Read-Host 'Username').Trim()
} while (-not $GuiUser)

$GuiRole = (Read-Host 'Role [administrator/analyst/investigator/reader] (Enter = administrator)').Trim()
if (-not $GuiRole) { $GuiRole = 'administrator' }

do {
    $s1 = Read-Host 'Password (min 12 chars)' -AsSecureString
    $s2 = Read-Host 'Confirm password'        -AsSecureString
    $p1 = (New-Object Net.NetworkCredential('', $s1)).Password
    $p2 = (New-Object Net.NetworkCredential('', $s2)).Password
    $ok = $true
    if ($p1 -ne $p2)      { Write-Warning 'Passwords do not match.'; $ok = $false }
    elseif ($p1.Length -lt 12) { Write-Warning 'Password must be at least 12 characters.'; $ok = $false }
} while (-not $ok)

& $Exe --config $ServerCfg user add $GuiUser $p1 --role $GuiRole
if ($LASTEXITCODE -ne 0) { throw 'user add failed' }
$p1 = $p2 = $null

# ------------------------------------------------------------------ 4. Firewall
Write-Step 'Configuring firewall'
Get-NetFirewallRule -DisplayName 'Velociraptor*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'Velociraptor Frontend (clients)' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $FrontendPort -RemoteAddress $AllowedSubnets -Profile Any | Out-Null
New-NetFirewallRule -DisplayName 'Velociraptor Block GUI/API from network' -Direction Inbound -Action Block `
    -Protocol TCP -LocalPort 8889, 8001, 8003 -RemoteAddress Any -Profile Any | Out-Null
# NOTE: loopback traffic is not filtered by Windows Firewall, so local GUI access still works.

# ------------------------------------------------------------------ 5. Run the server at startup
# NOTE: "velociraptor service install" only sets up the CLIENT service, so the server
# is run in "frontend" mode from a startup scheduled task instead.
Write-Step 'Registering Velociraptor server as a startup task'
$TaskName = 'Velociraptor Server'
Lock-Path $InstallDir @('*S-1-5-32-545:(OI)(CI)RX')   # Users may read/execute the binary only

function Register-VeloTask([string]$UserId, [string]$RunLevel) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $action  = New-ScheduledTaskAction -Execute $Exe -Argument "--config `"$ServerCfg`" frontend -v"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $prin    = New-ScheduledTaskPrincipal -UserId $UserId -LogonType ServiceAccount -RunLevel $RunLevel
    $set     = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
                   -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable `
                   -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $prin -Settings $set | Out-Null
}
function Wait-Port([int]$Port, [int]$Seconds = 40) {
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

$runAs = 'SYSTEM'
if ($RunAsLocalService) {
    Write-Host 'Granting NT AUTHORITY\LOCAL SERVICE access to the datastore, logs and config'
    Lock-Path $Datastore @('*S-1-5-19:(OI)(CI)M')
    Lock-Path $LogDir    @('*S-1-5-19:(OI)(CI)M')
    Lock-Path $ServerCfg @('*S-1-5-19:R')
    Register-VeloTask 'NT AUTHORITY\LOCAL SERVICE' 'Limited'
    $runAs = 'LOCAL SERVICE'
} else {
    Register-VeloTask 'SYSTEM' 'Highest'
}

Start-ScheduledTask -TaskName $TaskName
$up = Wait-Port 8889

if (-not $up -and $RunAsLocalService) {
    Write-Warning 'Server did not come up as LOCAL SERVICE. Falling back to SYSTEM.'
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Get-Process -Name velociraptor -ErrorAction SilentlyContinue | Stop-Process -Force
    Register-VeloTask 'SYSTEM' 'Highest'
    $runAs = 'SYSTEM'
    Start-ScheduledTask -TaskName $TaskName
    $up = Wait-Port 8889
}
if (-not $up) { Write-Warning "GUI port 8889 is not listening. Check the logs in $LogDir" }
$frontendUp = [bool](Get-NetTCPConnection -State Listen -LocalPort $FrontendPort -ErrorAction SilentlyContinue)

# ------------------------------------------------------------------ 6. Summary
Write-Host "`n================ DONE ================" -ForegroundColor Green
Write-Host "Server task    : $TaskName (runs as $runAs, starts at boot)"
Write-Host "GUI listening  : $up   Frontend ($FrontendPort) listening: $frontendUp"
Write-Host "GUI            : https://127.0.0.1:8889  (local only, self-signed cert)"
Write-Host "GUI login      : $GuiUser (role: $GuiRole), with the password you entered"
Write-Host "Clients connect: https://${ServerName}:$FrontendPort/ (allowed from: $($AllowedSubnets -join ', '))"
Write-Host "Server config  : $ServerCfg   (contains CA private key; back up OFFLINE, never distribute)"
Write-Host "Client config  : $ClientCfg   (safe to distribute to endpoints)"
Write-Host "`nTo enroll an endpoint (elevated PowerShell on that host):"
Write-Host "  velociraptor.exe --config client.config.yaml service install"
try { [Net.Dns]::GetHostAddresses($ServerName) | Out-Null }
catch { Write-Warning "'$ServerName' does not resolve. Clients cannot connect until it is in DNS or a hosts file, or you rerun with the server's IP as -ServerName." }
Write-Host "`nReminder: the server name must stay reachable and stable. If this host's address changes, clients lose it."