<#
.SYNOPSIS
  Installs the Velociraptor CLIENT on a Windows endpoint.

.DESCRIPTION
  Put velociraptor.exe (or the release .msi) and client.config.yaml next to this script, then run
  from an elevated PowerShell prompt:
      Set-ExecutionPolicy -Scope Process Bypass
      .\Install-VelociraptorClient.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'client.config.yaml'),
    [string]$ExePath,
    [string]$MsiPath
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ConfigPath)) { throw "client config not found: $ConfigPath" }
if (Select-String -Path $ConfigPath -Pattern 'PRIVATE KEY' -Quiet) {
    throw "REFUSING: $ConfigPath contains a private key. That is the SERVER config. Use client.config.yaml only."
}

# Locate the binary
if (-not $ExePath -and -not $MsiPath) {
    $exe = Get-ChildItem $PSScriptRoot -Filter 'velociraptor*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $msi = Get-ChildItem $PSScriptRoot -Filter 'velociraptor*.msi' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($exe) { $ExePath = $exe.FullName } elseif ($msi) { $MsiPath = $msi.FullName }
}
if ($MsiPath) {
    Write-Host "Extracting binary from $MsiPath (extract only, no install)"
    $tmp = Join-Path $env:TEMP "velo_msi_$(Get-Random)"
    $p = Start-Process msiexec.exe -ArgumentList "/a `"$MsiPath`" /qn TARGETDIR=`"$tmp`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec extract failed ($($p.ExitCode))" }
    $ExePath = (Get-ChildItem $tmp -Recurse -Filter 'velociraptor*.exe' | Select-Object -First 1).FullName
}
if (-not $ExePath -or -not (Test-Path $ExePath)) { throw 'No velociraptor.exe or .msi found. Use -ExePath or -MsiPath.' }

$sig = Get-AuthenticodeSignature $ExePath
Write-Host "SHA256:    $((Get-FileHash $ExePath -Algorithm SHA256).Hash)"
Write-Host "Signature: $($sig.Status) $($sig.SignerCertificate.Subject)"
if ($sig.Status -ne 'Valid') {
    Write-Warning 'Binary is not validly signed.'
    if ((Read-Host 'Continue anyway? (y/N)') -ne 'y') { exit 1 }
}

# Reachability check against the server in the config
$m = Select-String -Path $ConfigPath -Pattern 'https?://([^/:\s"]+):?(\d+)?' | Select-Object -First 1
if ($m) {
    $h = $m.Matches[0].Groups[1].Value
    $port = if ($m.Matches[0].Groups[2].Value) { [int]$m.Matches[0].Groups[2].Value } else { 443 }
    $t = Test-NetConnection $h -Port $port -WarningAction SilentlyContinue
    if ($t.TcpTestSucceeded) { Write-Host "Server reachable: ${h}:$port" -ForegroundColor Green }
    else { Write-Warning "Cannot reach ${h}:$port right now (firewall, route, or server down). Installing anyway." }
}

# Remove any existing client service so the exe isn't locked
if (Get-Service Velociraptor -ErrorAction SilentlyContinue) {
    Stop-Service Velociraptor -Force -ErrorAction SilentlyContinue
    & sc.exe delete Velociraptor | Out-Null
    Start-Sleep -Seconds 2
}

& $ExePath --config $ConfigPath service install
if ($LASTEXITCODE -ne 0) { throw 'service install failed' }
Start-Service Velociraptor -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

$st = (Get-Service Velociraptor -ErrorAction SilentlyContinue).Status
if ($st -eq 'Running') {
    Write-Host 'OK: Velociraptor client is running. Check the host in the server GUI (search bar > Show All).' -ForegroundColor Green
} else {
    Write-Warning "Service status: $st. Check the logs under C:\Program Files\Velociraptor."
}