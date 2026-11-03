<#
.SYNOPSIS
    CCDC Windows Puller - Downloads Windows scripts and tools from the JMU-CDC public repository.

.DESCRIPTION
    Pulls scripts and binaries from:
    https://raw.githubusercontent.com/JMU-CDC/CCDC-Pub/refs/heads/main/

.EXAMPLE
    .\win-puller.ps1
    Interactive menu mode to select one or multiple items, all scripts, or all tools.

.EXAMPLE
    .\win-puller.ps1 -Selection "1,3,5" -Destination "C:\Tools"

.EXAMPLE
    .\win-puller.ps1 -Scripts -Destination "C:\Tools\Scripts"

.EXAMPLE
    .\win-puller.ps1 -All -Destination "C:\Tools"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Selection,

    [Parameter(Position = 1)]
    [string]$Destination = ".\CCDC-Windows",

    [switch]$All,
    [switch]$Scripts,
    [switch]$Tools,
    [switch]$Unzip
)

# Enable TLS 1.2 for older PowerShell / Windows versions
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Ignore if not supported
}

# Repository configuration
$RepoBase = "https://raw.githubusercontent.com/JMU-CDC/CCDC-Pub/refs/heads/main"

# Catalog of Windows Scripts and Tools
$Manifest = @(
    # --- Windows Scripts ---
    [PSCustomObject]@{
        Id          = 1
        Category    = "Scripts"
        Name        = "Find-LinksAndAliases.ps1"
        RelativeUri = "Windows/Scripts/Find-LinksAndAliases.ps1"
        Size        = "15 KB"
        Description = "Audit junctions, symlinks, and aliases"
    },
    [PSCustomObject]@{
        Id          = 2
        Category    = "Scripts"
        Name        = "PrivescCheck.ps1"
        RelativeUri = "Windows/Scripts/PrivescCheck.ps1"
        Size        = "955 KB"
        Description = "Windows privilege escalation enumeration"
    },
    [PSCustomObject]@{
        Id          = 3
        Category    = "Scripts"
        Name        = "Setup-Sysmon.ps1"
        RelativeUri = "Windows/Scripts/Setup-Sysmon.ps1"
        Size        = "9 KB"
        Description = "Automated Sysmon installer / updater"
    },
    [PSCustomObject]@{
        Id          = 4
        Category    = "Scripts"
        Name        = "sysmonconfig.xml"
        RelativeUri = "Windows/Scripts/sysmonconfig.xml"
        Size        = "32 KB"
        Description = "Sysmon modular configuration profile"
    },

    # --- Windows Tools ---
    [PSCustomObject]@{
        Id          = 5
        Category    = "Tools"
        Name        = "BLUESPAWN-client-x64.zip"
        RelativeUri = "Windows/Tools/BLUESPAWN-client-x64.zip"
        Size        = "3.8 MB"
        Description = "EDR & active defense tool"
    },
    [PSCustomObject]@{
        Id          = 6
        Category    = "Tools"
        Name        = "Firefox Setup 158.0.1.msi"
        RelativeUri = "Windows/Tools/Firefox Setup 158.0.1.msi"
        Size        = "95.0 MB"
        Description = "Firefox browser installer"
    },
    [PSCustomObject]@{
        Id          = 7
        Category    = "Tools"
        Name        = "floss.exe"
        RelativeUri = "Windows/Tools/floss.exe"
        Size        = "34.2 MB"
        Description = "FLARE Obfuscated String Solver"
    },
    [PSCustomObject]@{
        Id          = 8
        Category    = "Tools"
        Name        = "optisys_x64.zip"
        RelativeUri = "Windows/Tools/optisys_x64.zip"
        Size        = "3.9 MB"
        Description = "Process and system inspection utility"
    },
    [PSCustomObject]@{
        Id          = 9
        Category    = "Tools"
        Name        = "systeminformer.zip"
        RelativeUri = "Windows/Tools/systeminformer.zip"
        Size        = "22.7 MB"
        Description = "Process Hacker / System Informer"
    },
    [PSCustomObject]@{
        Id          = 10
        Category    = "Tools"
        Name        = "thor-lite-windows_10.7.32.zip"
        RelativeUri = "Windows/Tools/thor-lite-windows_10.7.32.zip"
        Size        = "43.7 MB"
        Description = "THOR Lite compromise / APT scanner"
    },
    [PSCustomObject]@{
        Id          = 11
        Category    = "Tools"
        Name        = "Wireshark-4.6.8-x64.exe"
        RelativeUri = "Windows/Tools/Wireshark-4.6.8-x64.exe"
        Size        = "98.9 MB"
        Description = "Wireshark network packet analyzer"
    }
)

function Show-Menu {
    Clear-Host
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "                     CCDC Windows Puller                         " -ForegroundColor Yellow
    Write-Host "  Repo: JMU-CDC/CCDC-Pub (refs/heads/main)                       " -ForegroundColor DarkGray
    Write-Host "=================================================================" -ForegroundColor Cyan

    Write-Host "`n[ Windows Scripts ]" -ForegroundColor Green
    foreach ($item in ($Manifest | Where-Object { $_.Category -eq "Scripts" })) {
        $idStr = "[{0,2}]" -f $item.Id
        Write-Host "  $idStr " -ForegroundColor Cyan -NoNewline
        Write-Host ("{0,-28}" -f $item.Name) -ForegroundColor White -NoNewline
        Write-Host ("({0,6})  " -f $item.Size) -ForegroundColor DarkGray -NoNewline
        Write-Host $item.Description -ForegroundColor Gray
    }

    Write-Host "`n[ Windows Tools ]" -ForegroundColor Green
    foreach ($item in ($Manifest | Where-Object { $_.Category -eq "Tools" })) {
        $idStr = "[{0,2}]" -f $item.Id
        Write-Host "  $idStr " -ForegroundColor Cyan -NoNewline
        Write-Host ("{0,-32}" -f $item.Name) -ForegroundColor White -NoNewline
        Write-Host ("({0,7})  " -f $item.Size) -ForegroundColor DarkGray -NoNewline
        Write-Host $item.Description -ForegroundColor Gray
    }

    Write-Host "`n[ Quick Presets ]" -ForegroundColor Magenta
    Write-Host "  [ A] " -ForegroundColor Cyan -NoNewline
    Write-Host "Download ALL items (Scripts + Tools)" -ForegroundColor White
    Write-Host "  [ S] " -ForegroundColor Cyan -NoNewline
    Write-Host "Download ALL Scripts (1-4)" -ForegroundColor White
    Write-Host "  [ T] " -ForegroundColor Cyan -NoNewline
    Write-Host "Download ALL Tools (5-11)" -ForegroundColor White
    Write-Host "  [ Q] " -ForegroundColor Cyan -NoNewline
    Write-Host "Quit" -ForegroundColor White
    Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan
}

function Download-FileWithProgress {
    param(
        [string]$Url,
        [string]$OutFile,
        [string]$DisplayName,
        [string]$SizeInfo
    )

    $parentDir = Split-Path -Path $OutFile -Parent
    if (-not (Test-Path -Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    Write-Host "[-] Downloading $DisplayName ($SizeInfo)... " -NoNewline -ForegroundColor Yellow

    try {
        # WebClient handles large binaries without slow PowerShell 5.1 GUI overhead
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "CCDC-WinPuller/1.0")
        $webClient.DownloadFile($Url, $OutFile)
        $webClient.Dispose()

        Write-Host "DONE" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Warning "WebClient error ($($_.Exception.Message)). Trying Invoke-WebRequest fallback..."
        try {
            $prevPref = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
            $ProgressPreference = $prevPref
            Write-Host "    [Fallback] Downloaded successfully: $DisplayName" -ForegroundColor Green
            return $true
        } catch {
            Write-Error "Failed to download $DisplayName : $($_.Exception.Message)"
            return $false
        }
    }
}

# Determine selection if running interactively
if (-not $All -and -not $Scripts -and -not $Tools -and [string]::IsNullOrWhiteSpace($Selection)) {
    Show-Menu
    $rawChoice = Read-Host "`nEnter selection (e.g. 1,3,5 or 1-4,10 or A/S/T/Q)"
    if ([string]::IsNullOrWhiteSpace($rawChoice) -or $rawChoice.Trim().ToUpper() -eq 'Q') {
        Write-Host "Exiting. No files downloaded." -ForegroundColor Yellow
        return
    }
    $Selection = $rawChoice.Trim()

    $destInput = Read-Host "Enter destination directory [Press Enter for default: '$Destination']"
    if (-not [string]::IsNullOrWhiteSpace($destInput)) {
        $Destination = $destInput.Trim().Trim('"').Trim("'")
    }
}

# Parse selected items
$selectedItems = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($All -or ($Selection -match '^(?i)A(LL)?$')) {
    $selectedItems.AddRange($Manifest)
} elseif ($Scripts -or ($Selection -match '^(?i)S(CRIPTS)?$')) {
    $selectedItems.AddRange(($Manifest | Where-Object { $_.Category -eq "Scripts" }))
} elseif ($Tools -or ($Selection -match '^(?i)T(OOLS)?$')) {
    $selectedItems.AddRange(($Manifest | Where-Object { $_.Category -eq "Tools" }))
} else {
    # Parse numbers, comma-separated lists, and ranges (e.g., "1, 3, 5", "1-4, 8", "1 2 5")
    $tokens = $Selection -split '[, ]+' | Where-Object { $_ -ne '' }
    $resolvedIds = [System.Collections.Generic.HashSet[int]]::new()

    foreach ($tok in $tokens) {
        if ($tok -match '^(\d+)-(\d+)$') {
            $start = [int]$matches[1]
            $end = [int]$matches[2]
            if ($start -gt $end) { $tmp = $start; $start = $end; $end = $tmp }
            for ($i = $start; $i -le $end; $i++) {
                [void]$resolvedIds.Add($i)
            }
        } elseif ($tok -match '^\d+$') {
            [void]$resolvedIds.Add([int]$tok)
        } elseif ($tok.ToUpper() -eq 'S') {
            foreach ($s in ($Manifest | Where-Object { $_.Category -eq "Scripts" })) { [void]$resolvedIds.Add($s.Id) }
        } elseif ($tok.ToUpper() -eq 'T') {
            foreach ($t in ($Manifest | Where-Object { $_.Category -eq "Tools" })) { [void]$resolvedIds.Add($t.Id) }
        } elseif ($tok.ToUpper() -eq 'A') {
            foreach ($a in $Manifest) { [void]$resolvedIds.Add($a.Id) }
        } else {
            Write-Warning "Unrecognized token: '$tok' (skipped)"
        }
    }

    foreach ($id in $resolvedIds) {
        $found = $Manifest | Where-Object { $_.Id -eq $id }
        if ($found) {
            $selectedItems.Add($found)
        } else {
            Write-Warning "Item ID [$id] not found in manifest."
        }
    }
}

if ($selectedItems.Count -eq 0) {
    Write-Warning "No valid items selected for download."
    return
}

# Ensure destination root exists
$resolvedDest = [System.IO.Path]::GetFullPath($Destination)
if (-not (Test-Path -Path $resolvedDest)) {
    New-Item -ItemType Directory -Path $resolvedDest -Force | Out-Null
}

Write-Host "`nTarget Destination: $resolvedDest" -ForegroundColor Cyan
Write-Host "Queue: $($selectedItems.Count) item(s) to download." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$successCount = 0
$failCount = 0

foreach ($item in $selectedItems) {
    $rawUrl = "$RepoBase/$($item.RelativeUri)"
    # Place scripts in Scripts/ and tools in Tools/ under destination, or flat
    $targetPath = Join-Path $resolvedDest (Join-Path $item.Category $item.Name)

    $ok = Download-FileWithProgress -Url $rawUrl -OutFile $targetPath -DisplayName "$($item.Category)/$($item.Name)" -SizeInfo $item.Size
    if ($ok) {
        $successCount++
        if ($Unzip -and $item.Name.EndsWith(".zip")) {
            $extractFolder = Join-Path (Split-Path -Path $targetPath -Parent) [System.IO.Path]::GetFileNameWithoutExtension($item.Name)
            try {
                Write-Host "    [+] Extracting to $extractFolder... " -NoNewline -ForegroundColor DarkYellow
                Expand-Archive -Path $targetPath -DestinationPath $extractFolder -Force
                Write-Host "DONE" -ForegroundColor Green
            } catch {
                Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
            }
        }
    } else {
        $failCount++
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Download Complete: $successCount succeeded, $failCount failed." -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "Files saved to: $resolvedDest`n" -ForegroundColor Cyan

