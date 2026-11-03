#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position=0)][ValidateNotNullOrEmpty()][string[]]$Path = @('.')
)

$linkCount = 0
$directoryCount = 0
$unreadableCount = 0
$visited = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$pending = New-Object 'System.Collections.Generic.Stack[string]'

function Get-LinkRecord {
    param([System.IO.FileSystemInfo]$Item)
    $type = [string]$Item.LinkType
    if (!$type) { $type = 'ReparsePoint' }
    [pscustomobject]@{
        Path = $Item.FullName
        LinkType = $type
        Target = (@($Item.Target) -join '; ')
    }
}

try {
    foreach ($scanPath in $Path) {
        try {
            $root = Get-Item -LiteralPath $scanPath -Force -ErrorAction Stop
            if ($root.PSProvider.Name -ne 'FileSystem') { throw 'Choose a filesystem path.' }
            if (!$visited.Add($root.FullName)) { continue }
            if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $linkCount++
                Get-LinkRecord $root
            } elseif ($root.PSIsContainer) {
                $pending.Push($root.FullName)
            }
        } catch {
            $unreadableCount++
            Write-Warning "Cannot read '${scanPath}': $($_.Exception.Message)"
        }
    }

    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $directoryCount++
        if ($directoryCount -eq 1 -or $directoryCount % 50 -eq 0) {
            Write-Progress -Id 1 -Activity 'Checking symbolic links and junctions' -Status "$directoryCount directories checked; $linkCount links found" -CurrentOperation $directory
        }
        try {
            $entries = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)
        } catch {
            $unreadableCount++
            Write-Warning "Cannot list '${directory}': $($_.Exception.Message)"
            continue
        }
        foreach ($entry in $entries) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                if (!$visited.Add($entry.FullName)) { continue }
                $linkCount++
                Get-LinkRecord $entry
            } elseif ($entry.PSIsContainer) {
                if ($visited.Add($entry.FullName)) { $pending.Push($entry.FullName) }
            }
        }
    }
} finally {
    Write-Progress -Id 1 -Activity 'Checking symbolic links and junctions' -Completed
}

Write-Host "Checked $directoryCount directories; found $linkCount link/reparse point(s)."
if ($unreadableCount) {
    Write-Warning "$unreadableCount location(s) could not be read. The scan is incomplete."
}
