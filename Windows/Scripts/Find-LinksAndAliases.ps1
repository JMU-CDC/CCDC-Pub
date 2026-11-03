#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position=0)][ValidateNotNullOrEmpty()][string[]]$Path = @('.'),
    [switch]$IncludeDefaults,
    [switch]$PassThru
)

$currentAliases = @(Microsoft.PowerShell.Utility\Get-Alias -ErrorAction Stop)

function Get-NativeLinkMetadata {
    param([string]$LiteralPath)
    if ($metadataState.InitializationError) { throw $metadataState.InitializationError }
    if (!('CcdcLinkMetadata.Reader' -as [type])) {
        try {
            Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace CcdcLinkMetadata {
    public sealed class LinkData {
        public string LinkType;
        public string Target;
        public string ReparseTag;
    }
    public static class Reader {
        [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(SafeFileHandle handle, uint code,
            IntPtr input, uint inputSize, [Out] byte[] output, uint outputSize,
            out uint returned, IntPtr overlapped);
        public static LinkData Read(string path) {
            using (SafeFileHandle handle = CreateFile(path, 0, 7, IntPtr.Zero, 3,
                0x02200000, IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                byte[] buffer = new byte[16384];
                uint returned;
                if (!DeviceIoControl(handle, 0x000900A8, IntPtr.Zero, 0, buffer,
                    (uint)buffer.Length, out returned, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (returned < 8 || returned > buffer.Length)
                    throw new InvalidDataException("Invalid reparse metadata header.");
                uint tag = BitConverter.ToUInt32(buffer, 0);
                LinkData result = new LinkData();
                result.ReparseTag = "0x" + tag.ToString("X8");
                int pathStart;
                if (tag == 0xA0000003) { result.LinkType = "Junction/MountPoint"; pathStart = 16; }
                else if (tag == 0xA000000C) { result.LinkType = "SymbolicLink"; pathStart = 20; }
                else { result.LinkType = "ReparsePoint"; return result; }
                int dataEnd = 8 + BitConverter.ToUInt16(buffer, 4);
                if (dataEnd < pathStart || dataEnd > returned)
                    throw new InvalidDataException("Invalid reparse metadata length.");
                int offset = BitConverter.ToUInt16(buffer, 8);
                int length = BitConverter.ToUInt16(buffer, 10);
                if ((offset % 2) != 0 || (length % 2) != 0 || length == 0 ||
                    pathStart + offset + length > dataEnd)
                    throw new InvalidDataException("Invalid stored link target.");
                string target = Encoding.Unicode.GetString(buffer, pathStart + offset, length);
                if (target.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase))
                    target = @"\\" + target.Substring(8);
                else if (target.StartsWith(@"\??\", StringComparison.Ordinal)) {
                    string rest = target.Substring(4);
                    target = rest.Length >= 3 && rest[1] == ':' && rest[2] == '\\'
                        ? rest : @"\\?\" + rest;
                }
                result.Target = target;
                return result;
            }
        }
    }
}
'@ -ErrorAction Stop
        } catch {
            $metadataState.InitializationError = "Native metadata reader could not load: $($_.Exception.Message)"
            throw $metadataState.InitializationError
        }
    }
    [CcdcLinkMetadata.Reader]::Read($LiteralPath)
}

function Get-LinkRecord {
    param($Item)
    $type = [string]$Item.LinkType
    $target = (@($Item.Target) -join '; ')
    $readStatus = 'PowerShell'
    $readError = ''
    if (!$type -or [string]::IsNullOrWhiteSpace($target)) {
        try {
            $native = & ${function:Get-NativeLinkMetadata} -LiteralPath $Item.FullName
            $type = $native.LinkType
            $target = $native.Target
            $readStatus = 'Native'
            if (!$target) {
                $target = "[No filesystem link target for tag $($native.ReparseTag)]"
            }
        } catch {
            $metadataState.Failures++
            $readStatus = 'Unavailable'
            $readError = $_.Exception.Message
            if ([string]::IsNullOrWhiteSpace($target)) { $target = '[Unreadable]' }
            Microsoft.PowerShell.Utility\Write-Warning "Cannot read link metadata for '$($Item.FullName)': $readError"
        }
    }
    if (!$type) { $type = 'ReparsePoint' }
    [pscustomobject]@{
        Path = $Item.FullName
        LinkType = $type
        Target = $target
        ReadStatus = $readStatus
        Error = $readError
    }
}


function Get-FileSystemLinkScan {
    param([string[]]$ScanRoots)
    $linkCount = 0
    $directoryCount = 0
    $unreadableCount = 0
    $metadataState = @{ Failures=0; InitializationError=$null }
    $visited = Microsoft.PowerShell.Utility\New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $pending = Microsoft.PowerShell.Utility\New-Object 'System.Collections.Generic.Stack[string]'

    $linkRecords = Microsoft.PowerShell.Utility\New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($scanPath in $ScanRoots) {
            try {
                $root = Microsoft.PowerShell.Management\Get-Item -LiteralPath $scanPath -Force -ErrorAction Stop
                if ($root.PSProvider.Name -ne 'FileSystem') { throw 'Choose a filesystem path.' }
                if (!$visited.Add($root.FullName)) { continue }
                if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $linkCount++
                    $linkRecords.Add((& ${function:Get-LinkRecord} $root))
                } elseif ($root.PSIsContainer) {
                    $pending.Push($root.FullName)
                }
            } catch {
                $unreadableCount++
                Microsoft.PowerShell.Utility\Write-Warning "Cannot read '${scanPath}': $($_.Exception.Message)"
            }
        }

        while ($pending.Count -gt 0) {
            $directory = $pending.Pop()
            $directoryCount++
            if ($directoryCount -eq 1 -or $directoryCount % 50 -eq 0) {
                Microsoft.PowerShell.Utility\Write-Progress -Id 1 -Activity 'Checking symbolic links and junctions' -Status "$directoryCount directories checked; $linkCount links found" -CurrentOperation $directory
            }
            try {
                $entries = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)
            } catch {
                $unreadableCount++
                Microsoft.PowerShell.Utility\Write-Warning "Cannot list '${directory}': $($_.Exception.Message)"
                continue
            }
            foreach ($entry in $entries) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    if (!$visited.Add($entry.FullName)) { continue }
                    $linkCount++
                    $linkRecords.Add((& ${function:Get-LinkRecord} $entry))
                } elseif ($entry.PSIsContainer) {
                    if ($visited.Add($entry.FullName)) { $pending.Push($entry.FullName) }
                }
            }
        }
    } finally {
        Microsoft.PowerShell.Utility\Write-Progress -Id 1 -Activity 'Checking symbolic links and junctions' -Completed
    }


    if ($unreadableCount) {
        Microsoft.PowerShell.Utility\Write-Warning "$unreadableCount location(s) could not be read. The scan is incomplete."
    }
    if ($metadataState.Failures) {
        Microsoft.PowerShell.Utility\Write-Warning "$($metadataState.Failures) link metadata read(s) failed. Link targets remain unverified; permissions were not changed."
    }
    [pscustomobject]@{
        Records = $linkRecords.ToArray()
        DirectoryCount = $directoryCount
        UnreadableCount = $unreadableCount
        MetadataFailureCount = $metadataState.Failures
    }
}

function Get-AliasComparison {
    param([object[]]$CurrentAliases, [switch]$IncludeDefaults)
    $baselineCode = @'
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$aliases = @(Microsoft.PowerShell.Utility\Get-Alias | Microsoft.PowerShell.Core\ForEach-Object {
    [pscustomobject]@{Name=$_.Name;Definition=$_.Definition;Options=[string]$_.Options}
})
[pscustomobject]@{Version=$PSVersionTable.PSVersion.ToString();Aliases=$aliases} |
    Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4 -Compress
'@
    $engineName = if ($PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
    $enginePath = [IO.Path]::Combine($PSHOME, $engineName)
    if (![IO.File]::Exists($enginePath)) { throw "Cannot find the current PowerShell engine: $enginePath" }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $enginePath
    $startInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($baselineCode))
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.Encoding]::UTF8
    $startInfo.StandardErrorEncoding = [Text.Encoding]::UTF8
    $helper = [Diagnostics.Process]::new()
    $helper.StartInfo = $startInfo
    try {
        if (!$helper.Start()) { throw 'Could not start the clean alias baseline process.' }
        $stdout = $helper.StandardOutput.ReadToEndAsync()
        $stderr = $helper.StandardError.ReadToEndAsync()
        if (!$helper.WaitForExit(15000)) {
            if (!$helper.HasExited) { $helper.Kill() }
            throw 'The clean alias baseline timed out after 15 seconds. No alias comparison was made.'
        }
        $outputText = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($helper.ExitCode -ne 0) { throw "The clean alias baseline failed: $errorText" }
        $baselineData = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $outputText -ErrorAction Stop
        if ($baselineData.Version -ne $PSVersionTable.PSVersion.ToString() -or !$baselineData.Aliases.Count) {
            throw 'The clean alias baseline is empty or uses a different PowerShell version. No comparison was made.'
        }
    } finally {
        $helper.Dispose()
    }

    $defaults = @{}
    foreach ($baselineAlias in $baselineData.Aliases) { $defaults[$baselineAlias.Name] = $baselineAlias }
    $differenceCount = 0
    $records = @(
        foreach ($currentAlias in ($currentAliases | Microsoft.PowerShell.Utility\Sort-Object Name)) {
            $baselineAlias = $defaults[$currentAlias.Name]
            if ($null -eq $baselineAlias) {
                $status = 'Added'
            } elseif ($currentAlias.Definition -ine $baselineAlias.Definition -or [string]$currentAlias.Options -ine $baselineAlias.Options) {
                $status = 'Changed'
            } else {
                $status = 'Default'
            }
            if ($status -ne 'Default') { $differenceCount++ }
            if ($status -ne 'Default' -or $IncludeDefaults) {
                [pscustomobject]@{
                    Name = $currentAlias.Name
                    Status = $status
                    CurrentTarget = $currentAlias.Definition
                    DefaultTarget = if ($null -ne $baselineAlias) { $baselineAlias.Definition } else { $null }
                    Options = [string]$currentAlias.Options
                    DefaultOptions = if ($null -ne $baselineAlias) { $baselineAlias.Options } else { $null }
                    Module = $currentAlias.ModuleName
                }
            }
        }
    )

    [pscustomobject]@{
        Records = $records
        CheckedCount = $CurrentAliases.Count
        DifferenceCount = $differenceCount
        BaselineVersion = $baselineData.Version
    }
}

$report = [pscustomobject]@{
    Links = @()
    Aliases = @()
    DirectoriesChecked = 0
    UnreadableLocations = 0
    UnreadableLinkMetadata = 0
    AliasesChecked = $currentAliases.Count
    AliasDifferences = 0
    AliasBaselineVersion = $null
    LinkError = ''
    AliasError = ''
    Complete = $false
}

Microsoft.PowerShell.Utility\Write-Host 'PowerShell aliases' -ForegroundColor Cyan
try {
    $aliasScan = & ${function:Get-AliasComparison} -CurrentAliases $currentAliases -IncludeDefaults:$IncludeDefaults
    $report.Aliases = @($aliasScan.Records)
    $report.AliasDifferences = $aliasScan.DifferenceCount
    $report.AliasBaselineVersion = $aliasScan.BaselineVersion
    if ($report.Aliases.Count) {
        $report.Aliases | Microsoft.PowerShell.Utility\Format-Table Name,Status,CurrentTarget,DefaultTarget -Wrap |
            Microsoft.PowerShell.Core\Out-Host
        $optionChanges = @($report.Aliases | Microsoft.PowerShell.Core\Where-Object {
            $_.Status -eq 'Changed' -and $_.Options -ine $_.DefaultOptions
        })
        if ($optionChanges.Count) {
            $optionChanges | Microsoft.PowerShell.Utility\Format-Table Name,Options,DefaultOptions -Wrap |
                Microsoft.PowerShell.Core\Out-Host
        }
    }
    Microsoft.PowerShell.Utility\Write-Host "Checked $($report.AliasesChecked) visible aliases against clean PowerShell $($report.AliasBaselineVersion); found $($report.AliasDifferences) added/changed alias(es)."
} catch {
    $report.AliasError = $_.Exception.Message
    Microsoft.PowerShell.Utility\Write-Warning "Alias comparison failed: $($report.AliasError)"
}

Microsoft.PowerShell.Utility\Write-Host "`nFilesystem links and junctions" -ForegroundColor Cyan
try {
    $linkScan = & ${function:Get-FileSystemLinkScan} -ScanRoots $Path
    $report.Links = @($linkScan.Records)
    $report.DirectoriesChecked = $linkScan.DirectoryCount
    $report.UnreadableLocations = $linkScan.UnreadableCount
    $report.UnreadableLinkMetadata = $linkScan.MetadataFailureCount
    if ($report.Links.Count) {
        $report.Links | Microsoft.PowerShell.Utility\Format-List Path,LinkType,Target,ReadStatus,Error |
            Microsoft.PowerShell.Core\Out-Host
    }
    Microsoft.PowerShell.Utility\Write-Host "Checked $($report.DirectoriesChecked) directories; found $($report.Links.Count) link/reparse point(s)."
} catch {
    $report.LinkError = $_.Exception.Message
    Microsoft.PowerShell.Utility\Write-Warning "Filesystem scan failed: $($report.LinkError)"
}

$report.Complete = !$report.LinkError -and !$report.AliasError -and
    $report.UnreadableLocations -eq 0 -and $report.UnreadableLinkMetadata -eq 0
if (!$report.Complete) {
    Microsoft.PowerShell.Utility\Write-Warning 'The combined scan is incomplete. Review errors and unreadable locations before interpreting missing results.'
}
if ($PassThru) { $report }

