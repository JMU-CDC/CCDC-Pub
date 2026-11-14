#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Guided', 'Audit', 'Apply')][string]$Mode = 'Guided',
    [string[]]$DomainClientAddress = @('Any'),
    [ValidateRange(1, 65535)][int[]]$ScoredTcpPort = @(53,5985,5986),
    [ValidateRange(1, 65535)][int[]]$ScoredUdpPort = @(53),
    [ValidateRange(0, 999)][Nullable[int]]$LockoutThreshold = $null,
    [switch]$ExportQuotientPasswords,
    [switch]$Defender,
    [string[]]$ResetUser = @(),
    [string[]]$DisableUser = @(),
    [string]$RecoveryAdminName,
    [string]$SystemStateBackupTarget,
    [string]$ReportRoot = "$env:ProgramData\CCDC\ServerAD"
)

$ErrorActionPreference = 'Stop'
$script:RunContext = $PSCmdlet
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:CanWriteReport = $false
$script:CreatedRecovery = $null
$script:FirewallServicesReady = $false
$script:SystemStateBackupVerified = $false

function Read-StepChoice {
    param([string]$Name)
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
        throw 'Existing timestamp profile markers are incomplete or duplicated; review the profile before changing it.'
    }
    if ($beginMatches.Count) {
        $start = $beginMatches[0].Index
        $finish = $endMatches[0].Index + $end.Length
        if ($finish -le $start) { throw 'Existing timestamp profile markers are out of order.' }
        $updated = $content.Substring(0,$start) + $block + $content.Substring($finish)
    } else {
        $separator = if ($content -and !$content.EndsWith("`n")) { [Environment]::NewLine } else { '' }
        $updated = $content + $separator + $block + [Environment]::NewLine
    }
    $profileTokens = $null
    $profileErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($updated, [ref]$profileTokens, [ref]$profileErrors)
    if ($profileErrors.Count) { throw 'The resulting PowerShell profile has syntax errors; the profile was not changed.' }
    if ($updated -cne $content) {
        $parent = Split-Path -Parent $ProfilePath
        if (!(Test-Path -LiteralPath $parent -PathType Container -ErrorAction Stop)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }
        if ($exists) {
            $backup = $ProfilePath + '.ccdc-backup-' + [guid]::NewGuid().ToString('N') + '.bak'
            Copy-Item -LiteralPath $ProfilePath -Destination $backup -ErrorAction Stop
            Write-Host "Original profile backed up to $backup"
        }
        [IO.File]::WriteAllText($ProfilePath, $updated, $encoding)
        if ([IO.File]::ReadAllText($ProfilePath,$encoding) -cne $updated) { throw 'PowerShell profile readback did not match.' }
    }
    & ([scriptblock]::Create($block))
    Write-Host "Timestamped prompts enabled now and saved for this user's future Windows PowerShell sessions: $ProfilePath"
    Write-Host 'Sessions started with -NoProfile or with profile execution blocked will not load this customization. Later host-specific profile code can override the prompt.'
}

function Invoke-Step {
    param([Alias('Name')][string]$StepName, [scriptblock]$Action,
        [ValidateSet('Completed','PendingRestart')][string]$CompletionStatus='Completed')
    $status = 'Skipped'
    $errorText = ''
    try {
        if (!$script:RunContext.ShouldProcess($StepName, 'Run guided plan action')) {
            $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
        } elseif (Read-StepChoice $StepName) {
            & $Action | Out-Host
            $status = $CompletionStatus
        }
    } catch [System.OperationCanceledException] {
        $errorText = $_.Exception.Message
    } catch {
        $status = 'Failed'
        $errorText = $_.Exception.Message
    }
    $script:Results.Add([pscustomobject]@{ Step=$StepName; Status=$status; Error=$errorText })
    if ($status -eq 'Failed') { Write-Warning "$StepName FAILED: $errorText. Review this before running the next action." }
    elseif ($errorText) { Write-Host "[$status] $StepName ($errorText)" }
    else { Write-Host "[$status] $StepName" }
    return ($status -eq 'Completed')
}

function Set-SmbRegistrySetting {
    param([ValidateSet('Server','Client')][string]$Side,
        [ValidateSet('SMB1','RequireSecuritySignature')][string]$SettingName, [int]$Value)
    if (($SettingName -eq 'SMB1' -and ($Side -ne 'Server' -or $Value -ne 0)) -or
        ($SettingName -eq 'RequireSecuritySignature' -and $Value -ne 1)) {
        throw 'Unsupported SMB hardening setting.'
    }
    $serviceName = if ($Side -eq 'Server') { 'LanmanServer' } else { 'LanmanWorkstation' }
    $service = @(Get-Service -ErrorAction Stop | Where-Object Name -eq $serviceName)
    if (!$service.Count) {
        throw [System.OperationCanceledException]::new("SMB $Side component is not installed ($serviceName is absent).")
    }
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\Parameters"
    try {
        if (!(Test-Path -LiteralPath $path -ErrorAction Stop)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -LiteralPath $path -Name $SettingName -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        if ((Get-ItemProperty -LiteralPath $path -Name $SettingName -ErrorAction Stop).$SettingName -ne $Value) {
            throw 'Saved SMB registry value did not match.'
        }
    } catch { throw "SMB registry update failed for '${path}\${SettingName}': $($_.Exception.Message)" }
    Write-Host "Saved and verified ${path}\${SettingName} = $Value. Restart required before treating this as active protection; no service or computer restart was performed."
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Read-ScManagerSecurityOutput {
    $output = @(& "$env:SystemRoot\System32\sc.exe" sdshow scmanager 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "SCM security query failed (exit $LASTEXITCODE): $($output -join ' ')" }
    return $output
}

function Get-ScManagerSddl {
    $output = @(Read-ScManagerSecurityOutput)
    $lines = @($output | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[OGDS]:' })
    if ($lines.Count -ne 1) { throw 'SCM query did not return one recognizable security descriptor.' }
    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($lines[0])
    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'SCM has no explicit DACL; review permissions manually.' }
    return $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
}

function Test-ScManagerNetworkDeny {
    param([string]$Sddl)
    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -is [System.Security.AccessControl.CommonAce] -and !$ace.IsCallback -and
            $ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied -and
            !([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -and
            $ace.SecurityIdentifier.Value -eq 'S-1-5-2' -and
            (($ace.AccessMask -band 0x10000000) -ne 0 -or ($ace.AccessMask -band 0x000F003F) -eq 0x000F003F)) {
            return $true
        }
    }
    return $false
}

function Add-ScManagerNetworkDeny {
    param([string]$Sddl)
    if (Test-ScManagerNetworkDeny $Sddl) { return $Sddl }
    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'Refusing to replace an absent SCM DACL.' }
    $networkSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-2')
    $deny = New-Object System.Security.AccessControl.CommonAce(
        [System.Security.AccessControl.AceFlags]::None,
        [System.Security.AccessControl.AceQualifier]::AccessDenied,
        0x10000000, $networkSid, $false, $null)
    $descriptor.DiscretionaryAcl.InsertAce(0, $deny)
    return $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
}

function Protect-ScManagerNetworkAccess {
    $before = Get-ScManagerSddl
    if (Test-ScManagerNetworkDeny $before) {
        Write-Host 'SCM already denies full access to network-logon identities; no permission change needed.'
        return
    }
    if (!$script:CanWriteReport) { throw 'Protected report directory was skipped or failed. SCM permissions were not changed because the original DACL cannot be saved.' }
    $after = Add-ScManagerNetworkDeny $before
    $backup = Join-Path $report ('scmanager-before-{0}.sddl' -f [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath $backup -Value $before -Encoding ASCII -ErrorAction Stop
    if ((Get-Content -LiteralPath $backup -Raw -ErrorAction Stop).Trim() -ne $before) { throw 'SCM DACL backup verification failed; permissions were not changed.' }
    Write-Host "Original SCM DACL saved at $backup. Restore locally with sc.exe sdset scmanager and that file's contents."
    try {
        Invoke-Native "$env:SystemRoot\System32\sc.exe" @('sdset','scmanager',$after)
        if (!(Test-ScManagerNetworkDeny (Get-ScManagerSddl))) { throw 'SCM readback did not contain the network-logon full-access deny entry.' }
    } catch {
        Write-Warning "SCM change failed or verification was inconclusive. Review local permissions; original DACL: $backup"
        throw
    }
    Write-Host 'SCM network-logon deny verified. Test required administration and scoring; existing handles and other execution methods are not covered.'
}

function Test-SecureStringEqual {
    param([securestring]$First, [securestring]$Second)
    if ($First.Length -ne $Second.Length) { return $false }
    $firstPtr = [IntPtr]::Zero
    $secondPtr = [IntPtr]::Zero
    try {
        $firstPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $secondPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        for ($i = 0; $i -lt $First.Length; $i++) {
            if ([Runtime.InteropServices.Marshal]::ReadInt16($firstPtr, $i * 2) -ne
                [Runtime.InteropServices.Marshal]::ReadInt16($secondPtr, $i * 2)) { return $false }
        }
        return $true
    } finally {
        if ($firstPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($firstPtr) }
        if ($secondPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPtr) }
    }
}

function Read-NewPassword {
    param([string]$Account)
    while ($true) {
        $first = Read-Host "New password for $Account" -AsSecureString
        $second = Read-Host "Confirm new password for $Account" -AsSecureString
        if ($null -eq $first -or $null -eq $second) { throw 'Secure password input is unavailable.' }
        $secondMatches = Test-SecureStringEqual $first $second
        $second.Dispose()
        if ($first.Length -gt 0 -and $secondMatches) { return $first }
        $first.Dispose()
        Write-Host 'Passwords must be nonempty and match. Try again.' -ForegroundColor Yellow
    }
}

function Get-SelectedUser {
    param([string]$Identity)
    $user = Get-ADUser -Identity $Identity -Properties ServicePrincipalName -Server $adServer
    if ($user.SID.Value -match '-(501|502)$' -or $user.SamAccountName -like 'krbtgt*') {
        throw "Reserved account $Identity is excluded from selected-user operations."
    }
    return $user
}

function Get-ReviewOperatorSid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-ReviewUser {
    param([ValidateSet('AD','Local')][string]$Scope,[string]$Identity)
    if ($Scope -eq 'AD') {
        $u=Get-ADUser -Identity $Identity -Properties Enabled,LockedOut,MemberOf,PrimaryGroupID,ServicePrincipalName -Server $adServer -ErrorAction Stop
        return [pscustomobject]@{Name=$u.SamAccountName;Sid=$u.SID.Value;Enabled=$u.Enabled;LockedOut=$u.LockedOut;MemberOf=@($u.MemberOf | Where-Object {$_});PrimaryGroupID=$u.PrimaryGroupID;SPNs=@($u.ServicePrincipalName | Where-Object {$_});Original=$u}
    }
    $u=Get-LocalUser -SID $Identity -ErrorAction Stop
    $state=Get-CimInstance Win32_UserAccount -Filter "SID='$($u.SID.Value)'" -ErrorAction Stop
    if ($null -eq $state) {throw 'Local account lockout state could not be read.'}
    return [pscustomobject]@{Name=$u.Name;Sid=$u.SID.Value;Enabled=$u.Enabled;LockedOut=$state.Lockout;MemberOf=@();PrimaryGroupID=$null;SPNs=@();Original=$u}
}

function Get-ReviewGroups {
    param([string]$Scope,$User)
    if ($Scope -eq 'AD') {
        $primarySid=($User.Sid -replace '-\d+$','')+'-'+$User.PrimaryGroupID
        foreach ($id in @($User.MemberOf)+@($primarySid)) {
            $g=Get-ADGroup -Identity $id -Server $adServer -ErrorAction Stop
            [pscustomobject]@{Name=$g.SamAccountName;Sid=$g.SID.Value;Primary=($g.SID.Value -eq $primarySid);Original=$g}
        }
    } else {
        foreach ($g in @(Get-LocalGroup -ErrorAction Stop)) {
            $members=@(Get-LocalGroupMember -SID $g.SID -ErrorAction Stop)
            if ($members.SID.Value -contains $User.Sid) {
                [pscustomobject]@{Name=$g.Name;Sid=$g.SID.Value;Primary=$false;Original=$g}
            }
        }
    }
}

function Unlock-ReviewLocalUser {
    param([string]$Name)
    $entry=[ADSI]("WinNT://$env:COMPUTERNAME/$Name,user")
    $entry.psbase.InvokeSet('IsAccountLocked',$false)
    $entry.SetInfo()
}

function Invoke-ReviewAccountChange {
    param([ValidateSet('AD','Local')][string]$Scope,[string]$Identity,
        [ValidateSet('Password','AddGroup','RemoveGroup','Disable','Enable','Unlock')][string]$Operation,
        [string]$GroupIdentity)
    $user=Get-ReviewUser $Scope $Identity
    Invoke-Step "$Operation for $Scope user $($user.Name) [$($user.Sid)] (review service/scoring dependencies)" {
        $user=Get-ReviewUser $Scope $Identity
        if ($user.Sid -match '-(501|502|503|504)$' -or $user.Name -like 'krbtgt*') {throw 'Reserved/service-recovery accounts are excluded from general account changes.'}
        $protected=@((Get-ReviewOperatorSid),$script:CreatedRecovery.SID.Value)
        if ($Operation -in @('Disable','RemoveGroup') -and ($user.Sid -match '-500$' -or $user.Sid -in $protected)) {
            throw 'Refusing to disable or remove groups from the built-in Administrator, current operator, or newly created recovery administrator.'
        }
        $groups=@(Get-ReviewGroups $Scope $user)
        if ($script:CanWriteReport) {
            [pscustomobject]@{Scope=$Scope;User=$user;Groups=$groups;Operation=$Operation;TimeUtc=(Get-Date).ToUniversalTime()} |
                Export-Clixml -LiteralPath (Join-Path $report ('account-before-'+[guid]::NewGuid().ToString('N')+'.xml')) -Depth 8
        }
        switch ($Operation) {
            Password {
                if ($user.SPNs.Count) {Write-Warning 'This account has SPNs; update dependent services after rotation.'}
                $secret=Read-NewPassword $user.Name
                try {
                    if ($Scope -eq 'AD') {
                        Set-ADAccountPassword -Identity $user.Original -Reset -NewPassword $secret -Server $adServer -ErrorAction Stop
                        Export-QuotientPassword -Account $user.Name -Secret $secret
                    } else {Set-LocalUser -SID $user.Sid -Password $secret -ErrorAction Stop}
                } finally {$secret.Dispose()}
            }
            {$_ -in @('AddGroup','RemoveGroup')} {
                $id=$GroupIdentity
                if (!$id) {$id=Read-Host 'Exact group name, SID, or AD distinguished name (blank cancels)'}
                if ([string]::IsNullOrWhiteSpace($id)) {throw [OperationCanceledException]::new('Group change canceled.')}
                if ($Scope -eq 'AD') {$group=Get-ADGroup -Identity $id -Server $adServer -ErrorAction Stop}
                else {
                    $found=@(Get-LocalGroup -ErrorAction Stop | Where-Object {$_.Name -ieq $id -or $_.SID.Value -eq $id})
                    if ($found.Count -ne 1) {throw 'Specify one exact existing local group.'}
                    $group=$found[0]
                }
                $membership=@($groups | Where-Object Sid -eq $group.SID.Value)
                if ($Operation -eq 'RemoveGroup' -and @($membership | Where-Object Primary).Count) {throw 'Primary AD group removal is not supported.'}
                $verb=if ($Operation -eq 'AddGroup') {'Add to'} else {'Remove from'}
                Invoke-Step "$verb group $($group.Name) [$($group.SID.Value)] for $Scope user $($user.Name)" {
                    if ($Scope -eq 'AD') {
                        if ($Operation -eq 'AddGroup') {Add-ADGroupMember -Identity $group -Members $user.Original -Server $adServer -ErrorAction Stop}
                        else {Remove-ADGroupMember -Identity $group -Members $user.Original -Server $adServer -Confirm:$false -ErrorAction Stop}
                    } else {
                        if ($Operation -eq 'AddGroup') {Add-LocalGroupMember -SID $group.SID -Member $user.Sid -ErrorAction Stop}
                        else {Remove-LocalGroupMember -SID $group.SID -Member $user.Sid -Confirm:$false -ErrorAction Stop}
                    }
                    $updated=Get-ReviewUser $Scope $Identity
                    $present=@(Get-ReviewGroups $Scope $updated | Where-Object Sid -eq $group.SID.Value).Count -gt 0
                    if ($present -ne ($Operation -eq 'AddGroup')) {throw 'Group membership readback did not match.'}
                } | Out-Null
            }
            Disable {
                if ($Scope -eq 'AD') {Disable-ADAccount -Identity $user.Original -Server $adServer -ErrorAction Stop}
                else {Disable-LocalUser -SID $user.Sid -ErrorAction Stop}
                if ((Get-ReviewUser $Scope $Identity).Enabled) {throw 'Account is still enabled.'}
            }
            Enable {
                if ($Scope -eq 'AD') {Enable-ADAccount -Identity $user.Original -Server $adServer -ErrorAction Stop}
                else {Enable-LocalUser -SID $user.Sid -ErrorAction Stop}
                if (!(Get-ReviewUser $Scope $Identity).Enabled) {throw 'Account is still disabled.'}
            }
            Unlock {
                if ($Scope -eq 'AD') {Unlock-ADAccount -Identity $user.Original -Server $adServer -ErrorAction Stop}
                else {Unlock-ReviewLocalUser $user.Name}
                if ((Get-ReviewUser $Scope $Identity).LockedOut) {throw 'Account still reports locked out.'}
            }
        }
    } | Out-Null
}

function Invoke-AccountReview {
    param([ValidateSet('AD','Local')][string]$Scope='AD')
    Write-Host 'Review each account. Enter or 7 advances unchanged; 0 ends review. Changes can interrupt unknown scoring accounts. Disable blocks sign-in; lockout is policy-driven, not deliberately induced.' -ForegroundColor Yellow
    if ($Scope -eq 'AD') {
        Write-Host 'DCs do not have ordinary local SAM users. DSRM is separate. Review member-server/workstation local users on those machines.'
        $identities=@(Get-ADUser -Filter * -Server $adServer -ErrorAction Stop | Sort-Object SamAccountName | ForEach-Object {$_.SID.Value})
        $resetSids=@($ResetUser | ForEach-Object {(Get-ReviewUser AD $_).Sid})
        $disableSids=@($DisableUser | ForEach-Object {(Get-ReviewUser AD $_).Sid})
    } else {$identities=@(Get-LocalUser -ErrorAction Stop | Sort-Object Name | ForEach-Object {$_.SID.Value});$resetSids=@();$disableSids=@()}
    foreach ($id in $identities) {
        $user=Get-ReviewUser $Scope $id
        if ($user.Sid -match '-(501|502|503|504)$' -or $user.Name -like 'krbtgt*') {Write-Host "Skipping reserved account: $($user.Name)";continue}
        if ($id -in $resetSids) {Invoke-ReviewAccountChange $Scope $id Password}
        if ($id -in $disableSids) {Invoke-ReviewAccountChange $Scope $id Disable}
        while ($true) {
            $user=Get-ReviewUser $Scope $id
            $groups=@(Get-ReviewGroups $Scope $user)
            Write-Host "`n$Scope user: $($user.Name) | SID: $id | Enabled: $($user.Enabled) | Locked: $($user.LockedOut)" -ForegroundColor Cyan
            $groups | Select-Object Name,Sid,Primary | Format-Table -AutoSize | Out-Host
            Write-Host 'Direct group memberships and primary group only; nested/inherited rights require further review.'
            Write-Host '1) Password  2) Add group  3) Remove group  4) Disable sign-in  5) Enable  6) Unlock  7/Enter) Next user  0) Finish review'
            $choice=Read-Host 'Choose an action'
            if ($null -eq $choice) {throw 'Interactive input unavailable.'}
            if ($choice -eq '0') {return}
            if ($choice -eq '' -or $choice -eq '7') {break}
            $operations=@{'1'='Password';'2'='AddGroup';'3'='RemoveGroup';'4'='Disable';'5'='Enable';'6'='Unlock'}
            if ($operations.ContainsKey($choice)) {Invoke-ReviewAccountChange $Scope $id $operations[$choice]}
            else {Write-Host 'Choose a listed action.'}
        }
    }
}

function Export-QuotientPassword {
    param([string]$Account, [securestring]$Secret)
    if (!$ExportQuotientPasswords) { return }
    Invoke-Step "Export changed password for $Account to a PLAINTEXT Quotient PCR CSV in the protected report directory" {
        if (!$script:CanWriteReport) { throw 'Password was changed, but CSV export requires the protected report directory. Submit the password to Quotient manually.' }
        $pointer = [IntPtr]::Zero
        $plaintext = $null
        $csv = $null
        try {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
            $plaintext = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
            $csv = '"{0}","{1}"' -f $Account.Replace('"','""'), $plaintext.Replace('"','""')
            $path = Join-Path $report 'Quotient-PCR-Export.csv'
            [IO.File]::AppendAllText($path, $csv + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        } finally {
            if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
            $plaintext = $null
            $csv = $null
        }
        Write-Host 'Plaintext CSV row saved. Submit through Quotient, verify scoring, and remove the file when no longer needed. Nothing was uploaded automatically.'
    } | Out-Null
}

function Get-KrbtgtMinimumWait {
    param([string]$PolicyText)
    $inside = $false
    $values = @{}
    foreach ($line in ($PolicyText -split '\r?\n')) {
        if ($line.Trim() -match '^\[(.+)\]$') { $inside = $Matches[1] -eq 'Kerberos Policy'; continue }
        if ($inside -and $line.Trim() -match '^(MaxTicketAge|MaxServiceAge)\s*=\s*(\d+)\s*$') {
            if ($values.ContainsKey($Matches[1])) { throw 'Duplicate Kerberos ticket lifetime setting; rotation was not started.' }
            $values[$Matches[1]] = [double]$Matches[2]
        }
    }
    if (!$values.ContainsKey('MaxTicketAge') -or !$values.ContainsKey('MaxServiceAge') -or $values.MaxTicketAge -le 0 -or $values.MaxServiceAge -le 0) {
        throw 'Could not verify finite effective user/service ticket lifetimes. KRBTGT rotation requires a reviewed Kerberos policy.'
    }
    $seconds = [math]::Max(36000, [math]::Max($values.MaxTicketAge * 3600, $values.MaxServiceAge * 60))
    return [timespan]::FromSeconds($seconds + 300)
}

function Get-KrbtgtKeyState {
    param([string]$Identity, [string]$Server)
    $account = Get-ADUser -Identity $Identity -Properties pwdLastSet,'msDS-KeyVersionNumber',Enabled -Server $Server -ErrorAction Stop
    if ($account.SID.Value -notmatch '-502$' -or $account.Enabled) { throw 'KRBTGT identity/state is unexpected; rotation was stopped.' }
    if ([long]$account.pwdLastSet -le 0 -or [int]$account.'msDS-KeyVersionNumber' -le 0) { throw 'KRBTGT key metadata is unavailable; rotation was stopped.' }
    [pscustomobject]@{Version=[int]$account.'msDS-KeyVersionNumber';PasswordLastSet=[long]$account.pwdLastSet}
}

function Assert-KrbtgtReplication {
    param([string]$Identity, [string]$Server, $Expected)
    $controllers = @(Get-ADDomainController -Filter * -Server $Server -ErrorAction Stop | Where-Object { !$_.IsReadOnly })
    if (!$controllers.Count) { throw 'No writable domain controllers were discovered.' }
    foreach ($controller in $controllers) {
        $target = $controller.HostName
        $failures = @(Get-ADReplicationFailure -Target $target -Scope Server -ErrorAction Stop | Where-Object FailureCount -gt 0)
        if ($failures.Count) { throw "Replication failures exist on $target." }
        $partners = @(Get-ADReplicationPartnerMetadata -Target $target -Scope Server -PartnerType Inbound -ErrorAction Stop)
        if ($controllers.Count -gt 1 -and !$partners.Count) { throw "No inbound replication partners could be verified on $target." }
        if (@($partners | Where-Object LastReplicationResult -ne 0).Count) { throw "An inbound replication check failed on $target." }
        $actual = Get-KrbtgtKeyState -Identity $Identity -Server $target
        if ($actual.Version -ne $Expected.Version -or $actual.PasswordLastSet -ne $Expected.PasswordLastSet) {
            throw "KRBTGT key metadata has not converged on $target, or another reset occurred."
        }
    }
}

function Wait-KrbtgtReplication {
    param([string]$Identity, [string]$Server, $Expected)
    $deadline = [datetime]::UtcNow.AddMinutes(10)
    while ($true) {
        try { Assert-KrbtgtReplication -Identity $Identity -Server $Server -Expected $Expected; return }
        catch {
            if ([datetime]::UtcNow -ge $deadline) { throw "KRBTGT replication was not verified within 10 minutes. No further reset will run. $($_.Exception.Message)" }
            Write-Warning $_.Exception.Message
            Start-Sleep -Seconds 30
        }
    }
}

function Reset-KrbtgtKeyOnce {
    param([string]$Identity, [string]$Server, $Expected,
        [Parameter(Mandatory)][securestring]$NewPassword)
    $current = Get-KrbtgtKeyState -Identity $Identity -Server $Server
    if ($current.Version -ne $Expected.Version -or $current.PasswordLastSet -ne $Expected.PasswordLastSet) {
        throw 'KRBTGT changed since the last check; no additional reset was performed.'
    }
    Set-ADAccountPassword -Identity $Identity -Reset -NewPassword $NewPassword -Server $Server -Confirm:$false -ErrorAction Stop
    $actual = Get-KrbtgtKeyState -Identity $Identity -Server $Server
    if ($actual.Version -ne ($Expected.Version + 1) -or $actual.PasswordLastSet -le $Expected.PasswordLastSet) {
        throw 'KRBTGT reset was attempted but metadata verification failed. Do not repeat the reset without reviewing its state.'
    }
    return $actual
}

function Invoke-KrbtgtRotation {
    if (!$script:CanWriteReport) {
        throw 'KRBTGT rotation requires protected report storage. Accept the report-directory step and resolve any storage errors before retrying.'
    }
    if (!$script:SystemStateBackupVerified) {
        Write-Warning 'No successful system-state backup was recorded in this run. Recovery readiness is unverified; -SystemStateBackupTarget remains available for a backup. This does not block the requested single reset.'
    }
    $localDc = Get-ADDomainController -Identity $env:COMPUTERNAME -Server $adServer -ErrorAction Stop
    if ($localDc.IsReadOnly -or $localDc.HostName -ine $domain.PDCEmulator) {
        throw 'Run the KRBTGT workflow locally on the writable PDC emulator so its effective ticket policy can be checked.'
    }
    $identity = "$($domain.DomainSID.Value)-502"
    $statePath = Join-Path $report 'krbtgt-rotation.json'
    $policyPath = Join-Path $report 'kerberos-policy.inf'
    Invoke-Native "$env:SystemRoot\System32\secedit.exe" @('/export','/mergedpolicy','/cfg',$policyPath,'/areas','SECURITYPOLICY','/quiet') | Out-Host
    $wait = Get-KrbtgtMinimumWait (Get-Content -LiteralPath $policyPath -Raw -ErrorAction Stop)
    $before = Get-KrbtgtKeyState -Identity $identity -Server $adServer
    Assert-KrbtgtReplication -Identity $identity -Server $adServer -Expected $before
    if (([datetime]::UtcNow - [datetime]::FromFileTimeUtc($before.PasswordLastSet)) -lt $wait) {
        throw 'KRBTGT was changed too recently. No reset was performed; inspect prior rotation records before retrying.'
    }
    $state = [ordered]@{Domain=$domain.DNSRoot;Server=$adServer;SystemStateBackupVerified=[bool]$script:SystemStateBackupVerified;Phase='ResetPending';Before=$before;After=$null}
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8 -ErrorAction Stop
    Write-Warning 'KRBTGT rotation is starting. Notify the AD/Windows, SQL, application and scoring operators. User/service passwords do not change; authentication may require recovery if dependencies or replication are unhealthy.'
    Write-Host 'Enter and confirm a password using the hidden prompts. Windows generates its own KRBTGT secret internally; this is not a normal login password and must not be submitted to scoring.'
    $secret = Read-NewPassword -Account krbtgt
    try { $after = Reset-KrbtgtKeyOnce -Identity $identity -Server $adServer -Expected $before -NewPassword $secret }
    finally { $secret.Dispose() }
    $state.After = $after
    $state.Phase = 'ResetApplied'
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8 -ErrorAction Stop
    Wait-KrbtgtReplication -Identity $identity -Server $adServer -Expected $after
    $state.Phase = 'Completed'
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8 -ErrorAction Stop
    Write-Host 'One KRBTGT reset replicated; no second reset is scheduled. Verify domain sign-in, DNS, SYSVOL, SQL, authenticated WinRM and Quotient scores. No passwords need to be submitted to Quotient for krbtgt.'
}

function Get-DefenderRuntimeStatus {
    try {
        $status = @(Get-MpComputerStatus -ErrorAction Stop)
        if ($status.Count -ne 1) { throw 'Defender status query did not return one result.' }
        return $status[0]
    }
    catch {
        $providerError = $_.Exception.Message
        try {
            $status = @(Get-WmiObject -Namespace 'root\Microsoft\Windows\Defender' -Class MSFT_MpComputerStatus -ErrorAction Stop)
            if ($status.Count -ne 1) { throw 'Legacy Defender status query did not return one result.' }
            Write-Warning "Defender CIM query failed: $providerError Read status through legacy WMI instead."
            return $status[0]
        } catch { $legacyError = $_.Exception.Message }
        $serviceState = 'unavailable'
        try { $serviceState = [string](Get-Service -Name WinDefend -ErrorAction Stop).Status } catch {}
        throw "Defender status is unverified. CIM: $providerError Legacy WMI: $legacyError WinDefend service: $serviceState. Signature updates and service presence do not prove real-time protection is active."
    }
}

function Enable-DefenderRealtimeProtection {
    $before = $null
    try { $before = Get-DefenderRuntimeStatus }
    catch { Write-Warning "Initial Defender status is unavailable: $($_.Exception.Message) The approved enable action will still be attempted through supported interfaces." }
    if ($null -ne $before -and $before.AMRunningMode -match 'Passive|EDR Block') {
        throw "Defender is in $($before.AMRunningMode) mode. Verify the primary antivirus product; active mode was not forced."
    }
    $service = Get-Service -Name WinDefend -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        Write-Host 'Starting the installed Microsoft Defender Antivirus service.'
        Start-Service -Name WinDefend -ErrorAction Stop
        $service.WaitForStatus('Running', [timespan]::FromSeconds(15))
    }
    if ((Get-Service -Name WinDefend -ErrorAction Stop).Status -ne 'Running') {
        throw 'WinDefend did not start. Review the service error and antivirus policy; no startup permissions or protection controls were changed.'
    }
    $enableRequested = $false
    if ($null -eq $before -or !$before.AMServiceEnabled -or !$before.AntivirusEnabled -or !$before.RealTimeProtectionEnabled) {
        Write-Host 'Requesting Microsoft Defender real-time protection ON (DisableRealtimeMonitoring=false).'
        try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }
        catch {
            $providerError = $_.Exception.Message
            Write-Warning "Defender CIM preference update failed: $providerError Trying the supported legacy WMI Set method."
            try {
                $preferenceClass = Get-WmiObject -Namespace 'root\Microsoft\Windows\Defender' -Class MSFT_MpPreference -List -ErrorAction Stop
                $parameters = $preferenceClass.GetMethodParameters('Set')
                $parameters['DisableRealtimeMonitoring'] = $false
                $result = $preferenceClass.InvokeMethod('Set', $parameters, $null)
                if ($null -eq $result -or $null -eq $result.ReturnValue -or [uint32]$result.ReturnValue -ne 0) {
                    throw "Defender legacy WMI Set did not return success (code: $($result.ReturnValue))."
                }
            } catch {
                throw "Real-time protection could not be enabled. CIM: $providerError Legacy WMI: $($_.Exception.Message) Review Defender policy, tamper protection and management-provider health."
            }
        }
        $enableRequested = $true
    }
    try { $after = Get-DefenderRuntimeStatus }
    catch {
        if ($enableRequested) {
            throw "The enable request was submitted, but protection status is still unverified: $($_.Exception.Message) Check Windows Security > Virus & threat protection > Manage settings > Real-time protection."
        }
        throw "Defender was reported active before this action, but final verification failed: $($_.Exception.Message)"
    }
    $after | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled
    if (!$after.AMServiceEnabled -or !$after.AntivirusEnabled -or !$after.RealTimeProtectionEnabled) {
        throw 'Defender real-time protection did not verify as active. Review effective policy and protection status; no protection controls were bypassed.'
    }
    Write-Host 'Microsoft Defender Antivirus and real-time protection verified ON.'
}

function Get-DefenderCommandPath {
    $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    if (Test-Path -LiteralPath $platformRoot -ErrorAction Stop) {
        $versions = @(Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction Stop | Where-Object Name -match '^\d+\.\d+\.\d+\.\d+(?:-|$)' |
            Sort-Object { [version](($_.Name -split '-')[0]) } -Descending)
        foreach ($directory in $versions) {
            $candidate = Join-Path $directory.FullName 'MpCmdRun.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction Stop) { return $candidate }
        }
    }
    $programFilesRoot = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $candidate = Join-Path $programFilesRoot 'Windows Defender\MpCmdRun.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction Stop) { return $candidate }
    throw 'MpCmdRun.exe was not found in the Defender platform or Program Files directory. Verify that Defender Antivirus is installed.'
}

function Update-DefenderSignatures {
    $providerError = 'Update-MpSignature is unavailable.'
    if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
        try {
            Update-MpSignature -ErrorAction Stop
            return
        } catch { $providerError = $_.Exception.Message }
    }
    Write-Warning "Defender PowerShell update failed: $providerError Trying the native signature updater."
    $commandPath = Get-DefenderCommandPath
    Write-Host "Running $commandPath -SignatureUpdate"
    Invoke-Native $commandPath @('-SignatureUpdate')
    Write-Host 'Native signature update command succeeded. This does not enable or verify real-time protection or ASR rules.'
}

function Invoke-DefenderDism {
    param([string[]]$Arguments, [int[]]$AllowedExitCode=@(0))
    $ErrorActionPreference = 'Continue'
    $output = @(& "$env:SystemRoot\System32\dism.exe" @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    if ($exitCode -notin $AllowedExitCode) {
        throw "DISM $($Arguments -join ' ') failed (exit $exitCode): $text"
    }
    [pscustomobject]@{ExitCode=$exitCode;Output=$text}
}

function Get-DefenderFeatureState {
    $result = Invoke-DefenderDism -Arguments @('/Online','/Get-FeatureInfo','/FeatureName:Windows-Defender','/English')
    $states = [regex]::Matches($result.Output, '(?im)^\s*State\s*:\s*([^\r\n]+)\s*$')
    if ($states.Count -ne 1) { throw 'DISM did not return one recognizable Windows-Defender feature state.' }
    $state = $states[0].Groups[1].Value.Trim()
    if ($state -notin @('Enabled','Disabled','Disabled with Payload Removed','Enable Pending','Disable Pending')) {
        throw "Unrecognized Defender feature state: $state"
    }
    return $state
}

function Get-DefenderInstallationStatus {
    $state = Get-DefenderFeatureState
    $services = @(Get-Service -ErrorAction Stop | Where-Object Name -eq 'WinDefend')
    $commandPath = $null
    try { $commandPath = Get-DefenderCommandPath } catch {}
    [pscustomobject]@{
        FeatureState=$state
        Installed=($state -eq 'Enabled' -and $services.Count -gt 0 -and !!$commandPath)
        ServiceState=if ($services.Count) { [string]$services[0].Status } else { 'Not found' }
        UpdaterPresent=[bool]$commandPath
        RestartNeeded=($state -in @('Enable Pending','Disable Pending'))
        ProtectionVerified=$false
    }
}

function Write-DefenderInstallRetry {
    $commands = @'
dism.exe /Online /Enable-Feature /FeatureName:Windows-Defender /All /NoRestart
if ($LASTEXITCODE -notin @(0,3010)) { throw 'Defender feature installation failed. Check DISM output, Windows Update/WSUS policy, or a matching Windows repair source.' }
if ($LASTEXITCODE -eq 3010) { Write-Warning 'Installation requires a planned reboot. Restart when coordinated, then rerun this file to update signatures.'; return }
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate
if ($LASTEXITCODE -ne 0) { throw 'Defender signature update failed. Review the updater output and verify protection separately.' }
Get-Service -Name WinDefend
try { $status = Get-MpComputerStatus -ErrorAction Stop }
catch { $status = Get-WmiObject -Namespace 'root\Microsoft\Windows\Defender' -Class MSFT_MpComputerStatus -ErrorAction Stop }
$status | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureVersion
if (!$status.AntivirusEnabled -or !$status.RealTimeProtectionEnabled) { throw 'Defender protection is not verified as active. Review the antivirus mode and effective policy.' }
'@
    Write-Host 'Defender installation retry command (run elevated when the required local/update source is available):' -ForegroundColor Yellow
    Write-Host 'dism.exe /Online /Enable-Feature /FeatureName:Windows-Defender /All /NoRestart'
    Write-Host 'Microsoft PowerShell alternative: Install-WindowsFeature -Name Windows-Defender'
    Write-Host 'An internet connection alone does not guarantee Windows Update/WSUS access. A removed payload may require matching Windows Server installation media or an approved repair source. No automatic reboot is requested.'
    if ($script:CanWriteReport) {
        $path = Join-Path $report 'Defender-Install-Later.ps1'
        Set-Content -LiteralPath $path -Value $commands -Encoding UTF8 -ErrorAction Stop
        Write-Host "Installation/update retry commands saved to $path"
    }
}

function Ensure-DefenderFeatureInstalled {
    try { $state = Get-DefenderFeatureState }
    catch {
        Write-DefenderInstallRetry
        throw "Could not determine whether the Defender feature is installed; no installation was attempted. $($_.Exception.Message)"
    }
    Write-Host "Native DISM Defender feature state: $state"
    if ($state -in @('Enable Pending','Disable Pending')) {
        Write-DefenderInstallRetry
        Write-Warning "Defender servicing is $state. Coordinate a reboot, then recheck/retry installation. Protection is not verified."
        return [pscustomobject]@{Outcome=$state;RestartNeeded=$true;ProtectionVerified=$false}
    }
    if ($state -eq 'Enabled') {
        $services = @(Get-Service -ErrorAction Stop | Where-Object Name -eq 'WinDefend')
        $commandPath = $null
        try { $commandPath = Get-DefenderCommandPath } catch {}
        if ($services.Count -and $commandPath) {
            Write-Host "Defender is installed; WinDefend service: $($services[0].Status). No reinstall was attempted. A running service and existing executable do not verify real-time protection or repair the CIM provider."
            return [pscustomobject]@{Outcome='Already installed';RestartNeeded=$false;ProtectionVerified=$false}
        }
        Write-DefenderInstallRetry
        Write-Host 'If Defender files were deleted or corrupted while the feature remained enabled, review these native OS repair commands separately:'
        Write-Host 'dism.exe /Online /Cleanup-Image /RestoreHealth'
        Write-Host 'sfc.exe /scannow'
        throw 'The Defender feature is enabled but its service or native updater is missing. Enabling an already-enabled feature cannot prove deleted files are repaired; inspect component-store/file integrity and the DISM log.'
    }
    Write-DefenderInstallRetry
    Write-Host 'Installing the missing Defender feature using native DISM. Local payload is used when available; configured update/repair sources may be needed.'
    try {
        $installation = Invoke-DefenderDism -Arguments @('/Online','/Enable-Feature','/FeatureName:Windows-Defender','/All','/NoRestart','/English') -AllowedExitCode @(0,3010)
        Write-Host $installation.Output
    } catch {
        throw "Defender installation could not complete. If offline or the update/repair source is unavailable, rerun the printed/saved command once access is restored. Installation is not verified. $($_.Exception.Message)"
    }
    if ($installation.ExitCode -eq 3010) {
        return [pscustomobject]@{Outcome='Installed; restart required';RestartNeeded=$true;ProtectionVerified=$false}
    }
    $after = Get-DefenderFeatureState
    if ($after -eq 'Enable Pending') {
        return [pscustomobject]@{Outcome='Installation pending restart';RestartNeeded=$true;ProtectionVerified=$false}
    }
    if ($after -ne 'Enabled') { throw "Defender installation returned success but feature readback is '$after'." }
    $services = @(Get-Service -ErrorAction Stop | Where-Object Name -eq 'WinDefend')
    if (!$services.Count) { throw 'Defender feature is enabled but WinDefend was not found after installation. Review servicing and restart requirements.' }
    $commandPath = Get-DefenderCommandPath
    Write-Host "Defender feature installation verified. WinDefend: $($services[0].Status); updater: $commandPath. Update signatures and verify real-time protection after any required reboot."
    [pscustomobject]@{Outcome='Installed';RestartNeeded=$false;ProtectionVerified=$false}
}

function Enable-LsassAsrRule {
    foreach ($command in 'Get-MpComputerStatus','Get-MpPreference','Add-MpPreference') {
        if (!(Get-Command $command -ErrorAction SilentlyContinue)) { throw "Required Defender command is unavailable: $command" }
    }
    $status = Get-DefenderRuntimeStatus
    if ($status.AMRunningMode -match 'Passive|EDR Block' -or !$status.AntivirusEnabled -or !$status.RealTimeProtectionEnabled) {
        throw 'ASR requires active Defender Antivirus and real-time protection. Verify the primary antivirus configuration.'
    }
    $ruleId = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
    $before = Get-MpPreference -ErrorAction Stop
    $existing = @{}
    $ids = @($before.AttackSurfaceReductionRules_Ids)
    $actions = @($before.AttackSurfaceReductionRules_Actions)
    if ($ids.Count -ne $actions.Count) { throw 'Existing ASR IDs/actions are inconsistent; settings were not changed.' }
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($ids[$i]) { $existing[[string]$ids[$i]] = [int]$actions[$i] }
    }
    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
    $after = Get-MpPreference -ErrorAction Stop
    $actual = @{}
    $ids = @($after.AttackSurfaceReductionRules_Ids)
    $actions = @($after.AttackSurfaceReductionRules_Actions)
    if ($ids.Count -ne $actions.Count) { throw 'ASR readback IDs/actions are inconsistent; review effective policy.' }
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($ids[$i]) { $actual[[string]$ids[$i]] = [int]$actions[$i] }
    }
    if (!$actual.ContainsKey($ruleId) -or $actual[$ruleId] -ne 1) { throw 'LSASS ASR rule did not read back in Block mode. Review effective policy.' }
    foreach ($id in $existing.Keys) {
        if ($id -ne $ruleId -and (!$actual.ContainsKey($id) -or $actual[$id] -ne $existing[$id])) {
            throw "Existing ASR rule changed unexpectedly: $id. Review effective policy."
        }
    }
    Write-Host 'LSASS ASR Block setting verified; test compatibility and review Defender events. This is not a guarantee that credential dumping is impossible.'
}

function Set-RegistryDword {
    param([string]$Description, [string]$Path, [string]$Name, [int]$Value,
        [ValidateSet('Completed','PendingRestart')][string]$CompletionStatus='Completed')
    $registryValueName = $Name
    Invoke-Step "$Description ($Name = $Value)" -CompletionStatus $CompletionStatus {
        $operation = 'check key'
        try {
            if (!(Test-Path -LiteralPath $Path -ErrorAction Stop)) {
                $operation = 'create key'
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            $operation = 'write DWORD value'
            New-ItemProperty -LiteralPath $Path -Name $registryValueName -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            $operation = 'verify DWORD value'
            if ((Get-ItemProperty -LiteralPath $Path -Name $registryValueName -ErrorAction Stop).$registryValueName -ne $Value) {
                throw 'Registry readback did not match.'
            }
        } catch {
            throw "Registry operation '$operation' failed for '${Path}\${registryValueName}': $($_.Exception.Message) [$($_.FullyQualifiedErrorId)]"
        }
    } | Out-Null
}

function Set-RegistryDwordDirect {
    param([string]$Description, [string]$Path, [string]$Name, [int]$Value,
        [ValidateSet('Completed','PendingRestart')][string]$CompletionStatus='Completed')
    $stepName = "$Description ($Name = $Value)"
    $operation = 'check key'
    try {
        if (!(Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            $operation = 'create key'
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        $operation = 'write DWORD value'
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        $operation = 'verify DWORD value'
        if ((Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name -ne $Value) {
            throw 'Registry readback did not match.'
        }
        $script:Results.Add([pscustomobject]@{ Step=$stepName; Status=$CompletionStatus; Error='' })
        Write-Host "[$CompletionStatus] $stepName"
    } catch {
        $errorMsg = "Registry operation '$operation' failed for '${Path}\${Name}': $($_.Exception.Message)"
        $script:Results.Add([pscustomobject]@{ Step=$stepName; Status='Failed'; Error=$errorMsg })
        Write-Warning "$stepName FAILED: $errorMsg"
    }
}

function Start-FirewallServices {
    foreach ($serviceName in 'BFE','MpsSvc') {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
            Start-Service -Name $serviceName -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [timespan]::FromSeconds(15))
        }
        if ((Get-Service -Name $serviceName -ErrorAction Stop).Status -ne 'Running') {
            throw "Required firewall service $serviceName is not running."
        }
    }
}

function Get-NativeFirewallPolicy {
    if (!$script:FirewallServicesReady) { throw 'Firewall service startup was skipped or failed; no firewall configuration was attempted.' }
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2 -ErrorAction Stop
        $modifyState = [int]$policy.LocalPolicyModifyState
    } catch { throw "Cannot read native firewall policy/modification state: $($_.Exception.Message)" }
    if ($modifyState -ne 0) {
        throw "Local firewall rules cannot take effect (policy modify state $modifyState). Review Group Policy or block-all-inbound settings."
    }
    return $policy
}

function Invoke-FirewallNetsh {
    param([string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $output = @(& "$env:SystemRoot\System32\netsh.exe" @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "netsh $($Arguments -join ' ') failed (exit $exitCode): $($output -join ' ')"
    }
    $output | Out-Host
}

function Set-NativeFirewallAllowRule {
    param([string]$RuleName, [ValidateSet('TCP','UDP','ICMPv4')][string]$Protocol, [string[]]$Port, [string[]]$Address=@('Any'))
    $operation = 'read existing native firewall policy'
    try {
        $policy = Get-NativeFirewallPolicy
        $protocolNumber = @{TCP=6;UDP=17;ICMPv4=1}[$Protocol]
        $remoteAddresses = if ($Address -contains 'Any' -or $Address -contains '*') { '*' } else { $Address -join ',' }
        $operation = 'enumerate existing rules'
        $existing = @($policy.Rules | Where-Object Name -eq $RuleName)
        if ($existing.Count -gt 1) { throw "Multiple firewall rules are named $RuleName; review them before changing policy." }
        if ($existing.Count -and ([int]$existing[0].Protocol -ne $protocolNumber -or $existing[0].ApplicationName -or $existing[0].ServiceName)) {
            throw "Existing rule $RuleName has a different protocol or an application/service restriction; review it manually."
        }
        $arguments = @('advfirewall','firewall',$(if ($existing.Count) { 'set' } else { 'add' }),'rule',"name=$RuleName")
        if ($existing.Count) { $arguments += 'new' }
        $arguments += @('dir=in','action=allow','enable=yes','profile=any','localip=any',
            "remoteip=$(if ($remoteAddresses -eq '*') { 'any' } else { $remoteAddresses })",'interfacetype=any','edge=no','security=notrequired',
            'description=CCDC domain controller inbound service access')
        if ($Protocol -eq 'ICMPv4') { $arguments += 'protocol=icmpv4:8,any' }
        else { $arguments += @("protocol=$Protocol","localport=$($Port -join ',')",'remoteport=any') }
        $operation = 'write rule with netsh'
        Invoke-FirewallNetsh -Arguments $arguments
        $operation = 'read back rule after netsh succeeded'
        $policy = Get-NativeFirewallPolicy
        $verified = $policy.Rules.Item($RuleName)
        if (!$verified.Enabled -or [int]$verified.Direction -ne 1 -or [int]$verified.Action -ne 1 -or
            [int]$verified.Protocol -ne $protocolNumber -or [int]$verified.Profiles -ne 2147483647 -or
            [string]$verified.LocalAddresses -ne '*' -or [string]$verified.InterfaceTypes -ne 'All' -or
            $verified.ApplicationName -or $verified.ServiceName -or
            (([string]$verified.RemoteAddresses -split ',' | Sort-Object) -join ',') -ne (($remoteAddresses -split ',' | Sort-Object) -join ',')) {
            throw "Native firewall rule $RuleName failed readback verification."
        }
        if ($Protocol -eq 'ICMPv4') {
            if ([string]$verified.IcmpTypesAndCodes -ne '8:*') { throw "ICMP rule $RuleName did not read back as echo-request access." }
        } elseif ((([string]$verified.LocalPorts -split ',' | Sort-Object) -join ',') -ne (($Port | Sort-Object) -join ',') -or [string]$verified.RemotePorts -ne '*') {
            throw "Native firewall rule $RuleName port readback did not match."
        }
    } catch { throw "Firewall rule '$RuleName' failed during '${operation}': $($_.Exception.Message) [$($_.FullyQualifiedErrorId)]" }
}

function Set-AllowRule {
    param([string]$Name, [string]$Protocol, [string[]]$Port, [string[]]$Address)
    $ruleName = "CCDC-AD-$Name"
    return (Invoke-Step "Allow $Protocol ports $($Port -join ',') from $($Address -join ',') [$ruleName]" {
        Set-NativeFirewallAllowRule -RuleName $ruleName -Protocol $Protocol -Port $Port -Address $Address
    })
}

function Set-NativeFirewallBlockRule {
    param([string]$RuleName, [ValidateSet('TCP','UDP')][string]$Protocol, [string[]]$Port)
    $operation = 'read existing native firewall policy'
    try {
        $policy = Get-NativeFirewallPolicy
        $protocolNumber = @{TCP=6;UDP=17}[$Protocol]
        $operation = 'enumerate existing rules'
        $existing = @($policy.Rules | Where-Object Name -eq $RuleName)
        if ($existing.Count -gt 1) { throw "Multiple firewall rules are named $RuleName; review them before changing policy." }
        if ($existing.Count -and ([int]$existing[0].Protocol -ne $protocolNumber -or $existing[0].ApplicationName -or $existing[0].ServiceName)) {
            throw "Existing rule $RuleName has a different protocol or an application/service restriction; review it manually."
        }
        $arguments = @('advfirewall','firewall',$(if ($existing.Count) { 'set' } else { 'add' }),'rule',"name=$RuleName")
        if ($existing.Count) { $arguments += 'new' }
        $arguments += @('dir=in','action=block','enable=yes','profile=any','localip=any',
            'remoteip=any','interfacetype=any','edge=no',
            'description=CCDC domain controller explicit inbound block (not scored)',
            "protocol=$Protocol","localport=$($Port -join ',')",'remoteport=any')
        $operation = 'write block rule with netsh'
        Invoke-FirewallNetsh -Arguments $arguments
        $operation = 'read back rule after netsh succeeded'
        $policy = Get-NativeFirewallPolicy
        $verified = $policy.Rules.Item($RuleName)
        if (!$verified.Enabled -or [int]$verified.Direction -ne 1 -or [int]$verified.Action -ne 0 -or
            [int]$verified.Protocol -ne $protocolNumber -or [int]$verified.Profiles -ne 2147483647 -or
            $verified.ApplicationName -or $verified.ServiceName) {
            throw "Native firewall block rule $RuleName failed readback verification."
        }
        if ((([string]$verified.LocalPorts -split ',' | Sort-Object) -join ',') -ne (($Port | Sort-Object) -join ',')) {
            throw "Native firewall block rule $RuleName port readback did not match."
        }
    } catch { throw "Firewall block rule '$RuleName' failed during '${operation}': $($_.Exception.Message) [$($_.FullyQualifiedErrorId)]" }
}

function Set-BlockRule {
    param([string]$Name, [string]$Protocol, [string[]]$Port)
    $ruleName = "CCDC-AD-Block-$Name"
    return (Invoke-Step "Block $Protocol ports $($Port -join ',') (not scored) [$ruleName]" {
        Set-NativeFirewallBlockRule -RuleName $ruleName -Protocol $Protocol -Port $Port
    })
}

function Set-NativeFirewallProfiles {
    param([ValidateSet('Enabled','DefaultPolicy','Logging')][string]$Setting)
    $policy = Get-NativeFirewallPolicy
    switch ($Setting) {
        Enabled {
            foreach ($profile in 1,2,4) {
                if ($policy.BlockAllInboundTraffic($profile)) { throw "Firewall profile $profile blocks all inbound exceptions; review policy before enabling enforcement." }
            }
            Invoke-FirewallNetsh @('advfirewall','set','allprofiles','state','on')
            foreach ($profile in 1,2,4) {
                if (!$policy.FirewallEnabled($profile)) { throw "Firewall profile $profile did not read back as enabled." }
            }
        }
        DefaultPolicy {
            Invoke-FirewallNetsh @('advfirewall','set','allprofiles','firewallpolicy','blockinbound,allowoutbound')
            foreach ($profile in 1,2,4) {
                if ([int]$policy.DefaultInboundAction($profile) -ne 0 -or [int]$policy.DefaultOutboundAction($profile) -ne 1) {
                    throw "Firewall profile $profile default-policy readback did not match."
                }
            }
        }
        Logging {
            Invoke-FirewallNetsh @('advfirewall','set','allprofiles','logging','allowedconnections','enable')
            Invoke-FirewallNetsh @('advfirewall','set','allprofiles','logging','droppedconnections','enable')
            Invoke-FirewallNetsh @('advfirewall','set','allprofiles','logging','maxfilesize','32767')
            Invoke-FirewallNetsh @('advfirewall','show','allprofiles','logging')
        }
    }
}

function Export-Evidence {
    param([string]$Name, [scriptblock]$Query, [switch]$Display)
    $stepName = "Export $Name"
    try {
        $data = & $Query
        if ($Display) {
            $data | Out-Host
        }
        if ($script:CanWriteReport) {
            $data | Export-Clixml -LiteralPath (Join-Path $report "$Name.xml") -Depth 4
        }
        $count = if ($null -eq $data) { 0 } elseif ($data -is [System.Collections.ICollection]) { $data.Count } else { @($data).Count }
        $script:Results.Add([pscustomobject]@{ Step=$stepName; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepName ($count item(s) saved)" -ForegroundColor Green
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepName; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepName FAILED: $($_.Exception.Message)"
    }
}

function Invoke-BaselineNative {
    param([string]$File,[string[]]$Arguments,[int]$MaximumExitCode=0)
    $output = @(& $File @Arguments 2>&1)
    if ($LASTEXITCODE -lt 0 -or $LASTEXITCODE -gt $MaximumExitCode) { throw "$File failed (exit $LASTEXITCODE): $($output -join ' ')" }
    return $output
}

function Invoke-DiscoveryQuery {
    param([string]$StageName, [scriptblock]$Query,
        [ValidateRange(1,120)][int]$TimeoutSeconds=15)
    Write-Host "[Discovery] $StageName (query wait limit: $TimeoutSeconds seconds)" -ForegroundColor Cyan
    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param([string]$QueryText)
            $ErrorActionPreference = 'Stop'
            & ([scriptblock]::Create($QueryText))
        } -ArgumentList $Query.ToString() -ErrorAction Stop
        $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds -ErrorAction Stop
        if (!$finished) { throw "$StageName timed out after $TimeoutSeconds seconds; its inventory is unavailable." }
        if ($job.State -ne 'Completed') {
            $reason = $job.ChildJobs[0].JobStateInfo.Reason
            throw "$StageName query ended in state $($job.State): $reason"
        }
        Receive-Job -Job $job -ErrorAction Stop
        Write-Host "[Discovery] $StageName finished."
    } catch {
        Write-Warning $_.Exception.Message
        throw
    } finally {
        if ($null -ne $job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
    }
}

function Get-ServiceBaseline {
    $issues = New-Object 'System.Collections.Generic.List[object]'
    $services = @()
    $processes = @()
    try {
        $services = @(Invoke-DiscoveryQuery 'Windows services (CIM)' {
            Get-CimInstance Win32_Service -OperationTimeoutSec 10 -ErrorAction Stop |
                Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId
        })
    } catch {
        $issues.Add([pscustomobject]@{Source='Service CIM fallback';Status='ManualRequired';Error="CIM failed: $($_.Exception.Message) Using Service Control Manager and registry; service process IDs are unavailable."})
        Write-Host '[Discovery] Reading service names/configuration through Service Control Manager and the registry.'
        $startModes = @{0='Boot';1='System';2='Auto';3='Manual';4='Disabled'}
        $services = @(foreach ($service in (Get-Service -ErrorAction Stop)) {
            $configuration = $null
            try {
                $configuration = Get-ItemProperty -LiteralPath (Join-Path 'HKLM:\SYSTEM\CurrentControlSet\Services' $service.Name) -ErrorAction Stop
            } catch {
                $issues.Add([pscustomobject]@{Source="Service registry: $($service.Name)";Status='ManualRequired';Error=$_.Exception.Message})
            }
            [pscustomobject]@{
                Name=$service.Name;DisplayName=$service.DisplayName;State=[string]$service.Status
                StartMode=$(if ($null -ne $configuration -and $null -ne $configuration.Start) {$startModes[[int]$configuration.Start]} else {$null})
                StartName=$configuration.ObjectName;PathName=$configuration.ImagePath;ProcessId=$null
            }
        })
        if (!$services.Count) { throw 'CIM service discovery failed and Service Control Manager returned no services. Backups cannot be selected reliably.' }
    }
    try {
        $processes = @(Invoke-DiscoveryQuery 'Processes (CIM)' {
            Get-CimInstance Win32_Process -OperationTimeoutSec 10 -ErrorAction Stop |
                Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
        })
    } catch {
        $issues.Add([pscustomobject]@{Source='Process CIM fallback';Status='ManualRequired';Error="CIM failed: $($_.Exception.Message) Using Get-Process; parent process IDs and command lines are unavailable."})
        Write-Host '[Discovery] Reading processes through Get-Process.'
        try {
            $processes = @(Get-Process -ErrorAction Stop | Select-Object Name,@{Name='ProcessId';Expression={$_.Id}},@{Name='ParentProcessId';Expression={$null}},@{Name='ExecutablePath';Expression={$_.Path}},@{Name='CommandLine';Expression={$null}})
        } catch {
            $issues.Add([pscustomobject]@{Source='Process fallback';Error=$_.Exception.Message})
        }
    }
    $endpoints = New-Object 'System.Collections.Generic.List[object]'
    $hints = @{21='FTP';22='SSH';25='SMTP';53='DNS';80='HTTP';110='POP3';123='NTP';143='IMAP';389='LDAP';443='HTTPS';445='SMB';636='LDAPS';1433='SQL';3389='RDP';5985='WinRM HTTP';5986='WinRM HTTPS';8000='Possible Splunk web';8089='Possible Splunk management';9997='Possible Splunk receiver'}
    foreach ($protocol in 'TCP','UDP') {
        try {
            $dnsPid = (Get-Process dns -ErrorAction SilentlyContinue).Id
            $items = if ($protocol -eq 'TCP') {
                @(Invoke-DiscoveryQuery 'TCP listeners' {
                    $dId = (Get-Process dns -ErrorAction SilentlyContinue).Id
                    Get-NetTCPConnection -State Listen -ErrorAction Stop |
                        Where-Object { $null -eq $dId -or $_.OwningProcess -ne $dId }
                })
            } else {
                @(Invoke-DiscoveryQuery 'UDP endpoints' {
                    $dId = (Get-Process dns -ErrorAction SilentlyContinue).Id
                    Get-NetUDPEndpoint -ErrorAction Stop |
                        Where-Object { $null -eq $dId -or $_.OwningProcess -ne $dId }
                })
            }
            foreach ($item in $items) {
                $processId = [int]$item.OwningProcess
                $endpoints.Add([pscustomobject]@{
                    Protocol=$protocol;Address=$item.LocalAddress;Port=$item.LocalPort;ProcessId=$processId
                    Process=(@($processes | Where-Object ProcessId -eq $processId).Name -join ',')
                    Services=(@($services | Where-Object { $_.ProcessId -eq $processId -and $processId -ne 0 }).Name -join ',')
                    Candidate=$(if ($hints.ContainsKey([int]$item.LocalPort)) {$hints[[int]$item.LocalPort]} else {'Unclassified: investigate'})
                })
            }
        } catch { $issues.Add([pscustomobject]@{Source="$protocol endpoints";Error=$_.Exception.Message}) }
    }
    $shares = @()
    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
        try {
            $shares = @(Invoke-DiscoveryQuery 'SMB shares' {
                Get-SmbShare -ErrorAction Stop | Select-Object Name,Path,Description,Special,ScopeName
            })
        }
        catch { $issues.Add([pscustomobject]@{Source='SMB shares';Error=$_.Exception.Message}) }
    }
    $features = @()
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try {
            $features = @(Invoke-DiscoveryQuery 'Installed Windows roles/features' -TimeoutSeconds 30 {
                Get-WindowsFeature -ErrorAction Stop | Where-Object Installed | Select-Object Name,DisplayName
            })
        }
        catch { $issues.Add([pscustomobject]@{Source='Windows roles/features';Error=$_.Exception.Message}) }
    }
    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
    $sites = ''; $vdirs = ''; $roots = @()
    if (Test-Path -LiteralPath $appcmd) {
        try {
            $iis = Invoke-DiscoveryQuery 'IIS/FTP sites and virtual directories' {
                $tool = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
                $siteOutput = @(& $tool list site /xml 2>&1)
                if ($LASTEXITCODE -ne 0) { throw "IIS site query failed: $($siteOutput -join ' ')" }
                $vdirOutput = @(& $tool list vdir /xml 2>&1)
                if ($LASTEXITCODE -ne 0) { throw "IIS directory query failed: $($vdirOutput -join ' ')" }
                [pscustomobject]@{Sites=($siteOutput -join [Environment]::NewLine);Vdirs=($vdirOutput -join [Environment]::NewLine)}
            }
            $sites = $iis.Sites
            $vdirs = $iis.Vdirs
            [xml]$parsed = $vdirs
            $roots = @($parsed.SelectNodes('/appcmd/VDIR') | ForEach-Object { $_.GetAttribute('physicalPath') } | Where-Object { $_ } | Sort-Object -Unique)
        } catch { $issues.Add([pscustomobject]@{Source='IIS/FTP site discovery';Error=$_.Exception.Message}) }
    }
    [pscustomobject]@{Computer=$env:COMPUTERNAME;TimeUtc=(Get-Date).ToUniversalTime().ToString('o');Services=$services;Processes=$processes;Endpoints=@($endpoints.ToArray());Features=$features;Shares=$shares;IisSitesXml=$sites;IisVdirsXml=$vdirs;ContentRoots=$roots;Issues=@($issues.ToArray())}
}

function Initialize-BaselineDirectory {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -LiteralPath $OutputDirectory -AclObject $acl -ErrorAction Stop
}

function Invoke-BaselineBackup {
    param([string]$Name,[string]$Kind,[scriptblock]$Action)
    $state = 'Skipped'; $detail = ''
    if ($DiscoveryOnly -or !$script:BaselineCanWrite) { $state='NotAttempted'; $detail='Discovery only or no report directory; no backup attempted.' }
    elseif ($script:BaselineContext.ShouldProcess($Name,'Create service backup')) {
        Write-Host "`nBACKUP: $Name [$Kind]" -ForegroundColor Cyan
        try { & $Action | Out-Host; $state='Completed' }
        catch { $state='Failed'; $detail=$_.Exception.Message; Write-Warning "$Name failed: $detail" }
    } else { $state='Preview' }
    $script:BaselineResults.Add([pscustomobject]@{Name=$Name;Kind=$Kind;Status=$state;Detail=$detail})
}

function Backup-BaselineDnsZone {
    param([string]$ZoneName,[string]$Directory)
    $null = New-Item -ItemType Directory -Path $Directory -Force
    Get-DnsServerZone -Name $ZoneName -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $Directory 'zone.xml') -Depth 8
    Get-DnsServerResourceRecord -ZoneName $ZoneName -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $Directory 'records.xml') -Depth 12
    $filename = 'CCDC-'+[guid]::NewGuid().ToString('N')+'.dns'
    Export-DnsServerZone -Name $ZoneName -FileName $filename -ErrorAction Stop
    $source = Join-Path "$env:SystemRoot\System32\dns" $filename
    if (!(Test-Path -LiteralPath $source)) { throw "DNS export not found at $source. Check the server's configured DNS directory." }
    Copy-Item -LiteralPath $source -Destination (Join-Path $Directory 'zone-export.dns') -ErrorAction Stop
    if ((Get-Item -LiteralPath (Join-Path $Directory 'zone-export.dns')).Length -eq 0) { throw 'DNS zone export is empty.' }
}

function Backup-BaselineContent {
    param([string]$Source,[string]$Destination)
    $sourcePath = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Source)).TrimEnd('\')
    $destinationPath = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if ($sourcePath -notmatch '^[A-Za-z]:\\' -or $sourcePath -match '^[A-Za-z]:$') { throw 'Only explicit local content directories are copied automatically; UNC/drive roots require manual backup.' }
    if ($destinationPath.Equals($sourcePath,[StringComparison]::OrdinalIgnoreCase) -or $destinationPath.StartsWith($sourcePath+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Backup destination is inside source content; choose another report directory.' }
    $item = Get-Item -LiteralPath $sourcePath -ErrorAction Stop
    if (!$item.PSIsContainer -or ([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint)) { throw 'Content root must be a local directory, not a reparse point.' }
    Get-Acl -LiteralPath $sourcePath | Export-Clixml -LiteralPath ($Destination+'-root-acl.xml')
    Invoke-BaselineNative "$env:SystemRoot\System32\robocopy.exe" @($sourcePath,$destinationPath,'/E','/COPY:DAT','/DCOPY:DAT','/XJ','/SL','/R:1','/W:1','/NP','/NFL','/NDL',"/LOG:$Destination-copy.log") 7 | Out-Host
    if (!(Test-Path -LiteralPath $destinationPath)) { throw 'Content copy returned without a destination directory.' }
}

function Backup-BaselineSystemState {
    param([string]$Target)
    if ($Target -notmatch '^[A-Za-z]:$' -and $Target -notmatch '^\\\\[^\\]+\\[^\\]+(?:\\.*)?$') { throw 'Use a backup volume such as E: or a dedicated UNC backup share.' }
    if ($Target.TrimEnd('\') -ieq $env:SystemDrive) { throw 'Select a dedicated backup volume/share rather than the Windows volume.' }
    if (!(Test-Path -LiteralPath ($Target.TrimEnd('\')+'\'))) { throw 'System-state backup destination is unavailable.' }
    Invoke-BaselineNative "$env:SystemRoot\System32\wbadmin.exe" @('start','systemstatebackup',"-backupTarget:$Target",'-quiet') | Out-Host
    Invoke-BaselineNative "$env:SystemRoot\System32\wbadmin.exe" @('get','versions',"-backupTarget:$Target") |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'AD-systemstate-catalog.txt') -Encoding UTF8
}

function Invoke-ServiceBaselineBackups {
    param($Inventory)
    $names = @($Inventory.Services.Name)
    Invoke-BaselineBackup 'All Windows service definitions (registry; not application data)' 'Configuration export' {
        $file = Join-Path $OutputDirectory 'services-registry.reg'
        Invoke-BaselineNative "$env:SystemRoot\System32\reg.exe" @('export','HKLM\SYSTEM\CurrentControlSet\Services',$file,'/y') | Out-Host
        if (!(Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length -eq 0) { throw 'Service registry export is missing or empty.' }
    }
    if ('DNS' -in $names) {
        try {
            Import-Module DnsServer -ErrorAction Stop
            $zones = @(Get-DnsServerZone -ErrorAction Stop)
            Invoke-BaselineBackup 'DNS zone inventory and forwarders' 'Configuration evidence' {
                $zones | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'DNS-zones.xml') -Depth 8
                Get-DnsServerForwarder -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'DNS-forwarders.xml') -Depth 8
            }
            $index=0
            foreach ($zone in $zones) {
                if ($zone.IsAutoCreated -or $zone.ZoneType -ne 'Primary') { continue }
                $index++
                Invoke-BaselineBackup "DNS zone $($zone.ZoneName)" 'Zone records/configuration snapshot; not full AD/DNS recovery' {
                    Backup-BaselineDnsZone $zone.ZoneName (Join-Path $OutputDirectory "DNS-zone-$index")
                }
            }
        } catch { $script:BaselineResults.Add([pscustomobject]@{Name='DNS backup discovery';Kind='Discovery';Status='Failed';Detail=$_.Exception.Message}) }
    }
    if (Test-Path -LiteralPath "$env:SystemRoot\System32\inetsrv\appcmd.exe") {
        Invoke-BaselineBackup 'IIS/FTP server configuration (not content, certificates, or databases)' 'Native IIS configuration backup' {
            $name = 'CCDC-'+[guid]::NewGuid().ToString('N')
            Invoke-BaselineNative "$env:SystemRoot\System32\inetsrv\appcmd.exe" @('add','backup',$name) | Out-Host
            $source = Join-Path "$env:SystemRoot\System32\inetsrv\backup" $name
            $target = Join-Path $OutputDirectory 'IIS-native-backup'
            Copy-Item -LiteralPath $source -Destination $target -Recurse -ErrorAction Stop
            $config = Join-Path $target 'applicationHost.config'
            if (!(Test-Path -LiteralPath $config) -or (Get-Item -LiteralPath $config).Length -eq 0) { throw 'IIS backup applicationHost.config is missing or empty.' }
            $name | Set-Content -LiteralPath (Join-Path $OutputDirectory 'IIS-backup-name.txt')
        }
        $index=0
        foreach ($root in $Inventory.ContentRoots) {
            $index++
            Invoke-BaselineBackup "IIS/FTP live content: $root (may take longer than five minutes)" 'File copy; not transaction-consistent' {
                Backup-BaselineContent $root (Join-Path $OutputDirectory "IIS-content-$index")
                $root | Set-Content -LiteralPath (Join-Path $OutputDirectory "IIS-content-$index-source.txt")
            }
        }
        $script:BaselineResults.Add([pscustomobject]@{Name='IIS/FTP external dependencies';Kind='Application-specific recovery';Status='ManualRequired';Detail='Back up TLS certificate private keys, IIS encryption keys, external databases/storage, and per-file ACLs separately. Appcmd configuration plus live file copies are not a portable whole-application backup.'})
    } elseif ('W3SVC' -in $names -or 'FTPSVC' -in $names) {
        $script:BaselineResults.Add([pscustomobject]@{Name='IIS/FTP';Kind='Configuration/content backup';Status='ManualRequired';Detail='IIS/FTP service exists but appcmd is unavailable; inspect sites and create native configuration/content backups manually.'})
    }
    if ('DHCPServer' -in $names) {
        Invoke-BaselineBackup 'DHCP server configuration and leases' 'Native DHCP export' {
            Import-Module DhcpServer -ErrorAction Stop
            $file = Join-Path $OutputDirectory 'DHCP-export.xml'
            Export-DhcpServer -File $file -Leases -Force -ErrorAction Stop
            if (!(Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length -eq 0) { throw 'DHCP export is missing or empty.' }
        }
    }
    if ('NTDS' -in $names) {
        Invoke-BaselineBackup 'AD Group Policy objects (not an AD database backup)' 'Native GPO backup' {
            Import-Module GroupPolicy -ErrorAction Stop
            $directory = Join-Path $OutputDirectory 'AD-GPOs'
            $null = New-Item -ItemType Directory -Path $directory
            Backup-GPO -All -Path $directory -Server $env:COMPUTERNAME -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'AD-GPO-backups.xml') -Depth 8
        }
        if ($SystemStateBackupTarget) {
            Invoke-BaselineBackup "AD system state to $SystemStateBackupTarget (potentially lengthy; requires Windows Server Backup)" 'System-state backup' {
                Backup-BaselineSystemState $SystemStateBackupTarget
                $script:SystemStateBackupVerified = $true
            }
        } else {
            $script:BaselineResults.Add([pscustomobject]@{Name='AD system state';Kind='System-state backup';Status='ManualRequired';Detail='No destination supplied. Rerun with -SystemStateBackupTarget E: or a dedicated UNC share. GPO/configuration exports do not back up AD DS.'})
        }
    }
    foreach ($service in @($Inventory.Services | Where-Object { $_.Name -like 'MSSQL*' -or $_.Name -in @('CertSvc','sshd') -or $_.Name -match 'FileZilla|hMail|Apache' })) {
        $script:BaselineResults.Add([pscustomobject]@{Name=$service.Name;Kind='Application-specific recovery';Status='ManualRequired';Detail='Discovered service requires its own data/configuration backup procedure; registry export is insufficient. SQL needs native database backups; AD CS needs CA database/private-key backup.'})
    }
    $script:BaselineResults.Add([pscustomobject]@{Name='Additional scored services';Kind='Discovery follow-up';Status='ManualRequired';Detail='Compare all listeners, processes, installed roles, IIS/FTP bindings, shares and the live scoring portal. Port hints cannot prove which services are scored; stopped/on-demand/UDP services may be missed.'})
}

function Invoke-InitialServiceBackups {
    param(
        [Parameter(Mandatory)]$Inventory,
        [string]$OutputDirectory,
        [switch]$DiscoveryOnly,
        [switch]$NoReport,
        [string]$SystemStateBackupTarget
    )
    $inventory=$Inventory
    $script:BaselineContext=$script:RunContext
    $script:BaselineResults=New-Object 'System.Collections.Generic.List[object]'
    $script:BaselineCanWrite=$false
    if (!$NoReport -and $script:BaselineContext.ShouldProcess($OutputDirectory,'Create protected discovery/backup report')) {
        Initialize-BaselineDirectory
        $script:BaselineCanWrite=$true
        $inventory | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'inventory.xml') -Depth 12
        $inventory.Services | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'services.csv') -NoTypeInformation
        $inventory.Processes | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'processes.csv') -NoTypeInformation
        $inventory.Endpoints | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'listeners.csv') -NoTypeInformation
        $inventory.Shares | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'shares.csv') -NoTypeInformation
        if ($inventory.IisSitesXml) { $inventory.IisSitesXml | Set-Content -LiteralPath (Join-Path $OutputDirectory 'IIS-sites.xml') }
        if ($inventory.IisVdirsXml) { $inventory.IisVdirsXml | Set-Content -LiteralPath (Join-Path $OutputDirectory 'IIS-vdirs.xml') }
    }
    foreach ($issue in $inventory.Issues) {
        $issueStatus = if ($issue.Status) { $issue.Status } else { 'Failed' }
        $script:BaselineResults.Add([pscustomobject]@{Name=$issue.Source;Kind='Discovery';Status=$issueStatus;Detail=$issue.Error})
        Write-Warning "$($issue.Source): $($issue.Error)"
    }
    Invoke-ServiceBaselineBackups $inventory
    if ($script:BaselineCanWrite) {
        $script:BaselineResults | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'backup-status.csv') -NoTypeInformation
        Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse | Where-Object Name -ne 'SHA256.csv' |
            Get-FileHash -Algorithm SHA256 | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'SHA256.csv') -NoTypeInformation
    }
    $script:BaselineResults | Format-Table -Wrap -AutoSize | Out-Host
    Write-Host 'Review backup-status.csv: Completed is limited to the listed backup kind; ManualRequired/Skipped/Failed are recovery gaps. Copy sensitive backups off-host to approved storage and test restoration.'
    [pscustomobject]@{OutputDirectory=$(if ($script:BaselineCanWrite) {$OutputDirectory} else {''});FailedCount=@($script:BaselineResults | Where-Object Status -eq 'Failed').Count;Results=@($script:BaselineResults.ToArray())}

}

function Assert-LocalDomainController {
    $computer = $null
    try {
        $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    } catch {
        Write-Warning "CIM domain-controller check failed: $($_.Exception.Message) Checking local AD DS and Active Directory instead. Other CIM-based actions may also fail."
    }
    if ($null -ne $computer) {
        if ($computer.DomainRole -notin 4, 5) { throw 'Run this AD plan on a domain controller.' }
        return
    }
    try {
        $ntds = Get-Service -Name NTDS -ErrorAction Stop
        if ($ntds.Status -ne 'Running') { throw 'The local AD DS (NTDS) service is not running.' }
        $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -Server $env:COMPUTERNAME -ErrorAction Stop
        if ($null -eq $dc) { throw 'Active Directory did not identify this computer as a domain controller.' }
    } catch {
        throw "Cannot verify this machine as an active local domain controller without CIM. No hardening actions were started. $($_.Exception.Message)"
    }
    Write-Host 'Local domain controller verified using AD DS and Active Directory; CIM/WMI still needs investigation.'
}

function Invoke-DefenderOnlyPlan {
    Write-Host 'Defender-only mode: install if missing, enable real-time protection and update signatures; exits without running the AD walkthrough.' -ForegroundColor Cyan
    if ($Mode -eq 'Audit') {
        Invoke-Step 'Check Defender installation (read-only)' { Get-DefenderInstallationStatus } | Out-Null
        Invoke-Step 'Review Microsoft Defender status (read-only)' { Get-DefenderRuntimeStatus } | Out-Null
    } else {
        $installationState = @{Ready=$false}
        $installationCompleted = Invoke-Step 'Check Defender installation and install its Windows Server feature if missing (native DISM; no automatic reboot)' {
            $installation = Ensure-DefenderFeatureInstalled
            $installation | Format-List | Out-Host
            if ($installation.RestartNeeded) {
                $script:Results.Add([pscustomobject]@{Step='Defender feature servicing';Status='PendingRestart';Error='Coordinate a reboot, then rerun .\DC.ps1 -Defender to enable protection and update signatures. No automatic reboot was performed.'})
                Write-Warning 'Defender installation needs a planned restart. Protection enabling and signature updates are deferred until after that restart.'
            } else {
                $installationState.Ready = $true
            }
        }
        $actions = [ordered]@{
            'Enable Microsoft Defender real-time protection and verify active status' = { Enable-DefenderRealtimeProtection }
            'Update Microsoft Defender signatures (uses native MpCmdRun if the PowerShell update fails)' = { Update-DefenderSignatures }
        }
        foreach ($stepName in $actions.Keys) {
            if (($installationCompleted -and $installationState.Ready) -or $WhatIfPreference) {
                Invoke-Step $stepName $actions[$stepName] | Out-Null
            } else {
                $reason = 'Installation check was skipped, failed, or requires a restart. Rerun -Defender after resolving it.'
                $script:Results.Add([pscustomobject]@{Step=$stepName;Status='Skipped';Error=$reason})
                Write-Host "[Skipped] $stepName ($reason)"
            }
        }
    }
    $script:Results | Format-Table -Wrap -AutoSize | Out-Host
    $failedSteps = @($script:Results | Where-Object Status -eq 'Failed')
    if ($failedSteps.Count) {
        Write-Warning "Defender-only run ended with $($failedSteps.Count) failed step(s). Review the errors above; protection is not verified by a successful signature update alone."
        return 1
    }
    Write-Host 'Defender-only run finished with no recorded failures. Review any skipped or previewed actions.'
    return 0
}

if ($Defender) {
    $defenderExitCode = Invoke-DefenderOnlyPlan
    exit $defenderExitCode
}

Import-Module ActiveDirectory -ErrorAction Stop
Assert-LocalDomainController
$adServer = $env:COMPUTERNAME
$domain = Get-ADDomain -Server $adServer
$administrator = Get-ADUser -Identity "$($domain.DomainSID.Value)-500" -Server $adServer
$report = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
Write-Host "Domain: $($domain.DNSRoot) | Main administrator: $($administrator.SamAccountName)" -ForegroundColor Green

Write-Host "`n0. Discover services, then back up before hardening" -ForegroundColor Cyan
$script:InitialServiceInventory = $null
Write-Host '[*] Discovering installed services/listeners/sites BEFORE any password or hardening changes...' -ForegroundColor Cyan
try {
    $script:InitialServiceInventory = Get-ServiceBaseline
    $epCount = if ($script:InitialServiceInventory.Endpoints) { $script:InitialServiceInventory.Endpoints.Count } else { 0 }
    $ftCount = if ($script:InitialServiceInventory.Features)  { $script:InitialServiceInventory.Features.Count } else { 0 }
    $shCount = if ($script:InitialServiceInventory.Shares)    { $script:InitialServiceInventory.Shares.Count } else { 0 }
    Write-Host "   Discovered $epCount listening endpoint(s), $ftCount feature(s), $shCount share(s)." -ForegroundColor Gray
    foreach ($issue in $script:InitialServiceInventory.Issues) { Write-Warning "$($issue.Source): $($issue.Error)" }
    $script:Results.Add([pscustomobject]@{ Step='Discover installed services/listeners/sites'; Status='Completed'; Error='' })
} catch {
    $script:Results.Add([pscustomobject]@{ Step='Discover installed services/listeners/sites'; Status='Failed'; Error=$_.Exception.Message })
    Write-Warning "Discovery failed: $($_.Exception.Message)"
}
try {
    Install-TimestampPrompt
    $script:Results.Add([pscustomobject]@{ Step='Persist timestamped PowerShell and child CMD prompts for the current user across PowerShell restarts'; Status='Completed'; Error='' })
} catch {
    $script:Results.Add([pscustomobject]@{ Step='Persist timestamped PowerShell and child CMD prompts for the current user across PowerShell restarts'; Status='Failed'; Error=$_.Exception.Message })
    Write-Warning "Failed to install timestamp prompt: $($_.Exception.Message)"
}

try {
    New-Item -ItemType Directory -Path $report -Force | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $report -AclObject $acl
    $script:CanWriteReport = $true
    $script:Results.Add([pscustomobject]@{ Step="Create protected report directory: $report"; Status='Completed'; Error='' })
    Write-Host "[Completed] Create protected report directory: $report"
} catch {
    $script:CanWriteReport = $false
    $script:Results.Add([pscustomobject]@{ Step="Create protected report directory: $report"; Status='Failed'; Error=$_.Exception.Message })
    Write-Warning "Create protected report directory FAILED: $($_.Exception.Message)"
}
Invoke-Step 'Back up ALL discovered services BEFORE password or hardening changes (one approval runs all supported backups)' {
    if ($null -eq $script:InitialServiceInventory) { throw 'Service discovery was skipped or failed. Rerun discovery before attempting service backups.' }
    $options = @{ Inventory=$script:InitialServiceInventory; OutputDirectory=(Join-Path $report 'ServiceBaseline'); DiscoveryOnly=($Mode -eq 'Audit'); NoReport=(!$script:CanWriteReport) }
    if ($SystemStateBackupTarget) { $options.SystemStateBackupTarget=$SystemStateBackupTarget }
    $baselineResult = Invoke-InitialServiceBackups @options
    if ($baselineResult.FailedCount -gt 0) { throw 'Service discovery/backups have failures. Review ServiceBaseline/backup-status.csv before proceeding; some recovery gaps may remain.' }
} | Out-Null
Export-Evidence 'Services-Before' { Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name, State, StartMode, StartName, PathName }
if ($script:CanWriteReport) {
    try {
        Invoke-Native netsh.exe @('advfirewall','export',(Join-Path $report 'firewall-before.wfw'))
        $script:Results.Add([pscustomobject]@{ Step='Export original firewall policy'; Status='Completed'; Error='' })
        Write-Host '[Completed] Export original firewall policy'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Export original firewall policy'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Export original firewall policy FAILED: $($_.Exception.Message)"
    }
    try {
        Invoke-Native auditpol.exe @('/backup',"/file:$(Join-Path $report 'audit-before.csv')")
        $script:Results.Add([pscustomobject]@{ Step='Export original audit policy'; Status='Completed'; Error='' })
        Write-Host '[Completed] Export original audit policy'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Export original audit policy'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Export original audit policy FAILED: $($_.Exception.Message)"
    }
}

if ($Mode -ne 'Audit') {
    Write-Host "`n1. Passwords and accounts" -ForegroundColor Cyan
    Invoke-Step 'Create backup administrator account AND automatically grant built-in Administrators membership: next prompts ask for its username and password' {
        $name = Read-Host 'Username for the NEW backup administrator account'
        if (!$name -and $RecoveryAdminName) { $name = $RecoveryAdminName }
        if ($name -notmatch '^[a-zA-Z0-9._-]{1,20}$') { throw 'Enter a new simple username (1-20 letters, digits, dots, underscores or hyphens).' }
        if (Get-ADUser -Filter "SamAccountName -eq '$name'" -Server $adServer) { throw "Account $name already exists; no password or privileges were changed." }
        $secret = Read-NewPassword $name
        try {
            $script:CreatedRecovery = New-ADUser -Name $name -SamAccountName $name -Path $domain.UsersContainer `
                -AccountPassword $secret -Enabled $true -PassThru -Server $adServer
            Add-ADGroupMember -Identity 'S-1-5-32-544' -Members $script:CreatedRecovery -Server $adServer
            $members = @(Get-ADGroupMember -Identity 'S-1-5-32-544' -Server $adServer)
            if ($members.SID.Value -notcontains $script:CreatedRecovery.SID.Value) { throw 'Administrator membership verification failed.' }
        } finally { $secret.Dispose() }
    } | Out-Null
    Invoke-Step 'Review every AD user: password, groups, enabled/disabled and locked/unlock status (each change is separately confirmed)' {
        Invoke-AccountReview -Scope AD
    } | Out-Null
    try {
        $guest = "$($domain.DomainSID.Value)-501"
        Disable-ADAccount -Identity $guest -Server $adServer
        if ((Get-ADUser -Identity $guest -Server $adServer).Enabled) { throw 'Guest is still enabled.' }
        $script:Results.Add([pscustomobject]@{ Step='Disable the domain Guest account'; Status='Completed'; Error='' })
        Write-Host '[Completed] Disable the domain Guest account'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Disable the domain Guest account'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Disable the domain Guest account FAILED: $($_.Exception.Message)"
    }
    try {
        $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (!(Test-Path -LiteralPath $lsaKey -ErrorAction Stop)) {
            New-Item -Path $lsaKey -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -LiteralPath $lsaKey -Name 'RestrictAnonymous' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        if ((Get-ItemProperty -LiteralPath $lsaKey -Name 'RestrictAnonymous' -ErrorAction Stop).RestrictAnonymous -ne 1) {
            throw 'Registry readback did not match.'
        }
        $script:Results.Add([pscustomobject]@{ Step='Restrict anonymous access (RestrictAnonymous = 1)'; Status='Completed'; Error='' })
        Write-Host '[Completed] Restrict anonymous access (RestrictAnonymous = 1)'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Restrict anonymous access (RestrictAnonymous = 1)'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Restrict anonymous access (RestrictAnonymous = 1) FAILED: $($_.Exception.Message)"
    }
    try {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -MinPasswordLength 12 -ComplexityEnabled $true -Server $adServer
        $script:Results.Add([pscustomobject]@{ Step='Set DOMAIN minimum password length to 12 characters and enable complexity'; Status='Completed'; Error='' })
        Write-Host '[Completed] Set DOMAIN minimum password length to 12 characters and enable complexity'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Set DOMAIN minimum password length to 12 characters and enable complexity'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Set DOMAIN minimum password length to 12 characters and enable complexity FAILED: $($_.Exception.Message)"
    }
    if ($null -ne $LockoutThreshold) {
        Invoke-Step "Set DOMAIN lockout threshold to $LockoutThreshold (0 disables lockout; nonzero uses 30-minute lockout/window; coordinate scoring)" {
            if ($LockoutThreshold -eq 0) {
                Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -LockoutThreshold 0 -Server $adServer
            } else {
                Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -LockoutThreshold $LockoutThreshold `
                    -LockoutDuration ([timespan]::FromMinutes(30)) -LockoutObservationWindow ([timespan]::FromMinutes(30)) -Server $adServer
            }
        } | Out-Null
    } else {
        Write-Host 'Existing domain lockout policy retained. Use -LockoutThreshold only after reviewing scoring dependencies; PasswordPolicy evidence shows the current default policy.'
    }
    Export-Evidence 'Accounts' { Get-ADUser -Filter * -Properties Enabled,LockedOut,MemberOf,PrimaryGroupID,LastLogonDate,Description,ServicePrincipalName,PasswordLastSet -Server $adServer }
    Export-Evidence 'Sessions' { Invoke-Native query.exe @('session') }

    Write-Host "`n2. Features and services" -ForegroundColor Cyan
    try {
        if (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue) {
            Remove-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE
        }
        $script:Results.Add([pscustomobject]@{ Step='Remove the current operator screensaver executable setting'; Status='Completed'; Error='' })
        Write-Host '[Completed] Remove the current operator screensaver executable setting'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Remove the current operator screensaver executable setting'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Remove the current operator screensaver executable setting FAILED: $($_.Exception.Message)"
    }
    foreach ($stickyKeysTarget in @(
        @{ Name = 'current operator'; Path = 'HKCU:\Control Panel\Accessibility\StickyKeys' },
        @{ Name = 'sign-in screen (.DEFAULT)'; Path = 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys' }
    )) {
        $stepSticky = "Disable Sticky Keys and the five-Shift shortcut for $($stickyKeysTarget.Name) (saved setting; verify after next sign-in/restart)"
        try {
            $key = $stickyKeysTarget.Path
            $exists = Test-Path -LiteralPath $key
            $previous = if ($exists) { (Get-ItemProperty -LiteralPath $key).Flags } else { $null }
            $flags = 510
            if ($null -ne $previous -and ![int]::TryParse([string]$previous, [ref]$flags)) {
                throw "Unexpected Sticky Keys Flags value at ${key}: $previous"
            }
            $disabledFlags = [string]($flags -band (-bnot 5))
            if (!$exists) { New-Item -Path $key -Force | Out-Null }
            New-ItemProperty -LiteralPath $key -Name Flags -Value $disabledFlags -PropertyType String -Force | Out-Null
            if ((Get-ItemProperty -LiteralPath $key -Name Flags).Flags -ne $disabledFlags) {
                throw 'Sticky Keys registry readback did not match.'
            }
            Write-Host "Sticky Keys Flags: '$previous' -> '$disabledFlags' at $key."
            Write-Host 'Saved for the next sign-in/restart; the active desktop may retain its cached setting. Verify five-Shift behavior afterward. Accessibility binaries and debugger redirects are not modified.'
            $script:Results.Add([pscustomobject]@{ Step=$stepSticky; Status='Completed'; Error='' })
            Write-Host "[Completed] $stepSticky"
        } catch {
            $script:Results.Add([pscustomobject]@{ Step=$stepSticky; Status='Failed'; Error=$_.Exception.Message })
            Write-Warning "$stepSticky FAILED: $($_.Exception.Message)"
        }
    }
    Invoke-Step 'Disable SMBv1 on the SMB server (native registry; restart required)' -CompletionStatus PendingRestart {
        Set-SmbRegistrySetting -Side Server -SettingName SMB1 -Value 0
    } | Out-Null
    Invoke-Step 'Require SMB SERVER signing (native registry; restart required)' -CompletionStatus PendingRestart {
        Set-SmbRegistrySetting -Side Server -SettingName RequireSecuritySignature -Value 1
    } | Out-Null
    Invoke-Step 'Require SMB CLIENT signing (native registry; restart required)' -CompletionStatus PendingRestart {
        Set-SmbRegistrySetting -Side Client -SettingName RequireSecuritySignature -Value 1
    } | Out-Null
    Invoke-Step 'Restrict network-logon access to Service Control Manager (PsExec-style service creation; also blocks legitimate remote service management; requires protected backup directory)' {
        Protect-ScManagerNetworkAccess
    } | Out-Null
    try {
        $llmnrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        if (!(Test-Path -LiteralPath $llmnrKey -ErrorAction Stop)) {
            New-Item -Path $llmnrKey -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -LiteralPath $llmnrKey -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        if ((Get-ItemProperty -LiteralPath $llmnrKey -Name 'EnableMulticast' -ErrorAction Stop).EnableMulticast -ne 0) {
            throw 'Registry readback did not match.'
        }
        $script:Results.Add([pscustomobject]@{ Step='Disable LLMNR (EnableMulticast = 0)'; Status='Completed'; Error='' })
        Write-Host '[Completed] Disable LLMNR (EnableMulticast = 0)'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Disable LLMNR (EnableMulticast = 0)'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Disable LLMNR (EnableMulticast = 0) FAILED: $($_.Exception.Message)"
    }
    $script:NetBiosAdapters = @()
    $stepNetBios = 'Discover IP-enabled adapters before changing NetBIOS (CIM failure skips NetBIOS changes)'
    try {
        $script:NetBiosAdapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)
        $script:Results.Add([pscustomobject]@{ Step=$stepNetBios; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepNetBios"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepNetBios; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepNetBios FAILED: $($_.Exception.Message)"
    }
    if ($script:NetBiosAdapters.Count -eq 0) {
        Write-Warning 'Adapter discovery was skipped or failed. NetBIOS settings were not changed; review CIM/WMI health before retrying.'
    }
    foreach ($nic in $script:NetBiosAdapters) {
        $stepNic = "Disable NetBIOS over TCP/IP on adapter: $($nic.Description)"
        try {
            $outcome = Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2} -ErrorAction Stop
            if ($outcome.ReturnValue -notin 0,1) { throw "NetBIOS change failed: $($outcome.ReturnValue)" }
            if ($outcome.ReturnValue -eq 1) { Write-Warning 'NetBIOS change needs a restart.' }
            $script:Results.Add([pscustomobject]@{ Step=$stepNic; Status='Completed'; Error='' })
            Write-Host "[Completed] $stepNic"
        } catch {
            $script:Results.Add([pscustomobject]@{ Step=$stepNic; Status='Failed'; Error=$_.Exception.Message })
            Write-Warning "$stepNic FAILED: $($_.Exception.Message)"
        }
    }
    foreach ($tunnel in 'teredo','6to4','isatap') {
        $stepTunnel = "Disable IPv6 $tunnel tunnel"
        try {
            $arguments = if ($tunnel -eq 'teredo') { @('interface','teredo','set','state','disabled') }
                else { @('interface','ipv6',$tunnel,'set','state','state=disabled') }
            Invoke-Native netsh.exe $arguments
            $script:Results.Add([pscustomobject]@{ Step=$stepTunnel; Status='Completed'; Error='' })
            Write-Host "[Completed] $stepTunnel"
        } catch {
            $script:Results.Add([pscustomobject]@{ Step=$stepTunnel; Status='Failed'; Error=$_.Exception.Message })
            Write-Warning "$stepTunnel FAILED: $($_.Exception.Message)"
        }
    }
    $stepIpv6Reg = 'Keep native IPv6 enabled and undo any previous DisabledComponents setting (restart required if previously disabled) (DisabledComponents = 0)'
    try {
        $tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
        if (!(Test-Path -LiteralPath $tcpip6Key -ErrorAction Stop)) {
            New-Item -Path $tcpip6Key -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -LiteralPath $tcpip6Key -Name 'DisabledComponents' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        if ((Get-ItemProperty -LiteralPath $tcpip6Key -Name 'DisabledComponents' -ErrorAction Stop).DisabledComponents -ne 0) {
            throw 'Registry readback did not match.'
        }
        $script:Results.Add([pscustomobject]@{ Step=$stepIpv6Reg; Status='PendingRestart'; Error='' })
        Write-Host "[PendingRestart] $stepIpv6Reg"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepIpv6Reg; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepIpv6Reg FAILED: $($_.Exception.Message)"
    }
    foreach ($serviceName in 'Spooler','RemoteRegistry') {
        $stepStop = "Stop service $serviceName"
        try {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            if ((Get-Service $serviceName -ErrorAction SilentlyContinue).Status -eq 'Running') { throw 'Service did not stop.' }
            $script:Results.Add([pscustomobject]@{ Step=$stepStop; Status='Completed'; Error='' })
            Write-Host "[Completed] $stepStop"
        } catch {
            $script:Results.Add([pscustomobject]@{ Step=$stepStop; Status='Failed'; Error=$_.Exception.Message })
            Write-Warning "$stepStop FAILED: $($_.Exception.Message)"
        }
        $stepDisable = "Disable service $serviceName startup"
        try {
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
            $script:Results.Add([pscustomobject]@{ Step=$stepDisable; Status='Completed'; Error='' })
            Write-Host "[Completed] $stepDisable"
        } catch {
            $script:Results.Add([pscustomobject]@{ Step=$stepDisable; Status='Failed'; Error=$_.Exception.Message })
            Write-Warning "$stepDisable FAILED: $($_.Exception.Message)"
        }
    }
    Invoke-Step 'Set WinRM startup to Automatic and start it (AD WinRM is scored; listeners/authentication are verified separately)' {
        Set-Service -Name WinRM -StartupType Automatic
        Start-Service -Name WinRM
        if ((Get-Service -Name WinRM).Status -ne 'Running') { throw 'WinRM did not start.' }
    } | Out-Null

    Write-Host "`n3. Firewall and connections" -ForegroundColor Cyan
    Write-Host 'Firewall backend: netsh rule writes and native API verification; no firewall CIM calls or COM rule setters.'
    $script:FirewallServicesReady = Invoke-Step 'Start BFE and Windows Defender Firewall services (existing firewall policy takes effect)' {
        Start-FirewallServices
    }
    $tcpReady = Set-AllowRule 'Domain-TCP' TCP @('53','88','135','389','445','464','636','3268','3269','49152-65535') $DomainClientAddress
    $udpReady = Set-AllowRule 'Domain-UDP' UDP @('53','88','123','389','464') $DomainClientAddress
    $scoredRulesReady = $true
    foreach ($port in $ScoredTcpPort) {
        if (!(Set-AllowRule "Scored-TCP-$port" TCP @("$port") @('Any'))) { $scoredRulesReady = $false }
    }
    foreach ($port in $ScoredUdpPort) {
        if (!(Set-AllowRule "Scored-UDP-$port" UDP @("$port") @('Any'))) { $scoredRulesReady = $false }
    }
    $icmpReady = Invoke-Step 'Allow inbound ICMPv4 echo requests for reachability/scoring checks' {
        Set-NativeFirewallAllowRule -RuleName CCDC-AD-ICMP -Protocol ICMPv4 -Address @('Any')
    }
    # RDP (3389) is confirmed not scored on the DC; block it explicitly rather than relying solely on the default-deny policy.
    Set-BlockRule 'RDP' TCP @('3389') | Out-Null

    # Zero-risk explicit blocks: not scored on DC, no AD service dependency on any of these inbound to the DC.
    Set-BlockRule 'SSH'             TCP @('22')       | Out-Null  # Scored on Splunk/Webmail hosts only
    Set-BlockRule 'Telnet'          TCP @('23')       | Out-Null  # Never needed
    Set-BlockRule 'FTP'             TCP @('20','21')  | Out-Null  # No FTP on DC
    Set-BlockRule 'MSSQL'           TCP @('1433')     | Out-Null  # MSSQL is on its own host; auth uses Kerberos/LDAP (already allowed)
    Set-BlockRule 'NetBIOS-Session' TCP @('139')      | Out-Null  # Modern Windows uses 445; NIC-level NetBIOS also being disabled

    # Conditional block: SMTP (25)
    # Query runs BEFORE the approval prompt so you can read the output and decide.
    Write-Host "`n[Pre-check] SMTP (25) inbound block - querying DC count and replication site links..." -ForegroundColor Cyan
    $script:SmtpAllDCs   = @(Get-ADDomainController -Filter * -Server $adServer -ErrorAction Stop)
    $script:SmtpLinks    = @()
    try {
        $script:SmtpLinks = @(Get-ADReplicationSiteLink -Filter * -Server $adServer -ErrorAction Stop |
            Where-Object { [string]$_.ReplicationMethod -eq 'SMTP' })
    } catch { Write-Warning "Could not query AD replication site links: $($_.Exception.Message)" }
    $script:SmtpAllDCs | Select-Object HostName,Site,IsReadOnly | Format-Table -AutoSize | Out-Host
    if ($script:SmtpLinks.Count) {
        Write-Warning "SMTP site links found: $($script:SmtpLinks.Name -join ', '). Blocking port 25 WILL break inter-site AD replication. Type n to skip."
    } else {
        Write-Host "No SMTP site links found. Replication is RPC-only - safe to block port 25. Press Enter to apply." -ForegroundColor Green
    }
    Invoke-Step 'Block SMTP (25) inbound (review pre-check output above before approving)' {
        if ($script:SmtpLinks.Count) {
            throw "SMTP-based site links exist ($($script:SmtpLinks.Name -join ', ')). Block was not applied."
        }
        Set-NativeFirewallBlockRule -RuleName 'CCDC-AD-Block-SMTP' -Protocol TCP -Port @('25')
    } | Out-Null

    # Conditional block: HTTP/HTTPS (80/443)
    # Query runs BEFORE the approval prompt so you can read the output and decide.
    Write-Host "`n[Pre-check] HTTP/HTTPS (80/443) inbound block - querying AD CS and IIS service state..." -ForegroundColor Cyan
    $script:HttpCertSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    $script:HttpW3Svc   = Get-Service -Name W3SVC   -ErrorAction SilentlyContinue
    Write-Host "CertSvc (AD CS): $(if ($script:HttpCertSvc) { $script:HttpCertSvc.Status } else { 'Not installed' })"
    Write-Host "W3SVC   (IIS)  : $(if ($script:HttpW3Svc)   { $script:HttpW3Svc.Status   } else { 'Not installed' })"
    $script:HttpWebEnrollRisk = ($script:HttpCertSvc -and $script:HttpCertSvc.Status -eq 'Running' -and
                                  $script:HttpW3Svc   -and $script:HttpW3Svc.Status   -eq 'Running')
    if ($script:HttpWebEnrollRisk) {
        Write-Warning "Both AD CS and IIS are running. Web Enrollment is likely active on 80/443. Blocking WILL break certificate services. Type n to skip."
    } elseif ($script:HttpCertSvc -and $script:HttpCertSvc.Status -eq 'Running') {
        Write-Warning "AD CS is running but IIS is absent/stopped. Web Enrollment is likely inactive, but verify before approving."
    } else {
        Write-Host "Neither AD CS Web Enrollment nor IIS detected as active - safe to block. Press Enter to apply." -ForegroundColor Green
    }
    Invoke-Step 'Block HTTP/HTTPS (80/443) inbound (review pre-check output above before approving)' {
        if ($script:HttpWebEnrollRisk) {
            throw 'AD CS and IIS are both running. Web Enrollment may be active; block was not applied.'
        }
        Set-NativeFirewallBlockRule -RuleName 'CCDC-AD-Block-HTTP'  -Protocol TCP -Port @('80')
        Set-NativeFirewallBlockRule -RuleName 'CCDC-AD-Block-HTTPS' -Protocol TCP -Port @('443')
    } | Out-Null

    $stepFwEnable = 'Enable Windows Firewall on all profiles after preparing AD allow rules'
    try {
        if (!$tcpReady -or !$udpReady -or !$scoredRulesReady -or !$icmpReady) {
            throw 'Required AD, scoring, or ICMP allow rules were skipped or failed. Firewall activation was not changed; review existing rules manually.'
        }
        Set-NativeFirewallProfiles -Setting Enabled
        $script:Results.Add([pscustomobject]@{ Step=$stepFwEnable; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepFwEnable"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepFwEnable; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepFwEnable FAILED: $($_.Exception.Message)"
    }
    $stepFwDefault = 'Block unmatched inbound traffic and allow outbound traffic'
    try {
        if (!$tcpReady -or !$udpReady -or !$scoredRulesReady -or !$icmpReady) {
            throw 'Required AD, scoring, or ICMP allow rules were skipped or failed. Default policy was not changed; review existing rules manually.'
        }
        Set-NativeFirewallProfiles -Setting DefaultPolicy
        $script:Results.Add([pscustomobject]@{ Step=$stepFwDefault; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepFwDefault"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepFwDefault; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepFwDefault FAILED: $($_.Exception.Message)"
    }
    $stepFwLogging = 'Enable firewall allowed/blocked traffic logging (32 MB per profile)'
    try {
        Set-NativeFirewallProfiles -Setting Logging
        $script:Results.Add([pscustomobject]@{ Step=$stepFwLogging; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepFwLogging"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepFwLogging; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepFwLogging FAILED: $($_.Exception.Message)"
    }
    Export-Evidence 'Connections' {
        try {
            $dnsPid = (Get-Process dns -ErrorAction SilentlyContinue).Id
            Get-NetTCPConnection -ErrorAction Stop |
                Where-Object { $null -eq $dnsPid -or $_.OwningProcess -ne $dnsPid } |
                Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
        }
        catch {
            Write-Warning "CIM connection query failed: $($_.Exception.Message) Exporting native netstat output instead."
            Invoke-Native "$env:SystemRoot\System32\netstat.exe" @('-ano')
        }
    }

    Write-Host "`n4. Audit and logging" -ForegroundColor Cyan
    Set-RegistryDwordDirect 'Use advanced audit subcategories instead of legacy audit policy' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
    $stepAuditpol = 'Enable success/failure auditing for all categories'
    try {
        Invoke-Native auditpol.exe @('/set','/category:*','/success:enable','/failure:enable')
        $script:Results.Add([pscustomobject]@{ Step=$stepAuditpol; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepAuditpol"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepAuditpol; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepAuditpol FAILED: $($_.Exception.Message)"
    }
    Set-RegistryDwordDirect 'Enable PowerShell script block logging' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    $stepModLog = 'Enable PowerShell module logging for all modules'
    try {
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        New-Item -Path "$key\ModuleNames" -Force | Out-Null
        New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
        $script:Results.Add([pscustomobject]@{ Step=$stepModLog; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepModLog"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepModLog; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepModLog FAILED: $($_.Exception.Message)"
    }
    $stepTranscript = 'Enable PowerShell transcription to the protected report directory'
    try {
        if (!$script:CanWriteReport) { throw 'Protected report directory was skipped or failed; transcription was not enabled.' }
        $transcripts = Join-Path $report 'Transcripts'
        New-Item -ItemType Directory -Path $transcripts -Force | Out-Null
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name EnableTranscripting -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name OutputDirectory -Value $transcripts -PropertyType String -Force | Out-Null
        $script:Results.Add([pscustomobject]@{ Step=$stepTranscript; Status='Completed'; Error='' })
        Write-Host "[Completed] $stepTranscript"
    } catch {
        $script:Results.Add([pscustomobject]@{ Step=$stepTranscript; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "$stepTranscript FAILED: $($_.Exception.Message)"
    }
    Set-RegistryDwordDirect 'Include command lines in process creation events' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Set-RegistryDwordDirect 'Enable UAC (may require a later reboot)' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    Set-RegistryDwordDirect 'Require administrator consent on the secure desktop' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
    Write-Host 'Defender installation, real-time protection enabling and signature updates run separately: .\DC.ps1 -Defender. This walkthrough only checks installation.'
    Write-Host "`n5. AD hardening and triage" -ForegroundColor Cyan
    Set-RegistryDword 'Require NTLMv2 and refuse LM/NTLMv1' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
    Set-RegistryDword 'Disable WDigest plaintext credential caching (verify after new logons/restart; no automatic restart)' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Invoke-Step 'Enable Defender LSASS credential-stealing ASR rule in Block mode (can affect software accessing LSASS)' {
        Enable-LsassAsrRule
    } | Out-Null
    Invoke-Step 'Review LSA protection compatibility and reboot/UEFI recovery plan before enabling RunAsPPL manually' {
        Write-Host 'RunAsPPL=1 requires a restart and can persist via a UEFI variable; incompatible LSA plugins can fail to load. Review CodeIntegrity events and firmware recovery first. RunAsPPL=2 is not a documented Server 2022 substitute. No PPL setting is changed here.'
    } | Out-Null
    Invoke-Step 'Review Zerologon/Follina patch status and vulnerable Netlogon exceptions; registry workarounds do not replace updates' {
        Write-Host 'Verify applicable Windows security updates. FullSecureChannelProtection is obsolete on updated DCs. Review the Allow vulnerable Netlogon secure channel connections GPO. Follina was patched in June 2022; no ms-msdt handler is deleted here.'
    } | Out-Null
}

Export-Evidence 'ServiceControlManagerSecurity' { Get-ScManagerSddl }
Export-Evidence 'Accounts' { Get-ADUser -Filter * -Properties Enabled,LockedOut,MemberOf,PrimaryGroupID,LastLogonDate,Description,ServicePrincipalName,PasswordLastSet -Server $adServer }
Export-Evidence 'PasswordPolicy' { Get-ADDefaultDomainPasswordPolicy -Server $adServer }
Export-Evidence 'Services-After' { Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,State,StartMode,StartName,PathName }
Export-Evidence 'ListeningPorts' {
    $dnsPid = (Get-Process dns -ErrorAction SilentlyContinue).Id
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $null -eq $dnsPid -or $_.OwningProcess -ne $dnsPid } |
        Select-Object LocalPort,OwningProcess | Sort-Object LocalPort
}
Export-Evidence 'Processes' { Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine }
Export-Evidence 'Tasks' { Get-ScheduledTask -ErrorAction Stop | Select-Object TaskPath,TaskName,State,Actions,Principal,Triggers }
Export-Evidence 'StartupRegistry' {
    foreach ($path in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon')) {
        if (Test-Path $path) { Get-ItemProperty $path }
    }
}
Export-Evidence 'WMI-Persistence' {
    foreach ($class in '__EventFilter','__EventConsumer','__FilterToConsumerBinding') { Get-CimInstance -Namespace root/subscription -ClassName $class -ErrorAction Stop }
}
Export-Evidence 'AccessibilityBinaries' {
    foreach ($name in 'sethc.exe','utilman.exe','narrator.exe','osk.exe','magnify.exe') {
        $file = Join-Path "$env:SystemRoot\System32" $name
        Get-FileHash -LiteralPath $file -Algorithm SHA256
        Get-AuthenticodeSignature -LiteralPath $file | Select-Object Path,Status,StatusMessage
    }
}
Export-Evidence 'KerberoastableAccounts' {
    Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName,PasswordLastSet -Server $adServer | Select-Object Name,ServicePrincipalName,PasswordLastSet
}
Export-Evidence 'PrivilegedGroups' {
    foreach ($sid in "$($domain.DomainSID.Value)-512",'S-1-5-32-544') {
        Get-ADGroupMember -Identity $sid -Server $adServer | Select-Object @{Name='GroupSID';Expression={$sid}},Name,SamAccountName,ObjectClass
    }
    $forestRoot = Get-ADDomain -Identity $domain.Forest -Server $domain.Forest
    Get-ADGroupMember -Identity "$($forestRoot.DomainSID.Value)-519" -Server $domain.Forest
}
Export-Evidence 'ReplicationACL' {
    (Get-Acl "AD:\$($domain.DistinguishedName)").Access | Where-Object {
        $_.ObjectType -in [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',[guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
            [guid]'89e95b76-444d-4c62-991a-0facbeda640c',[guid]::Empty -or "$($_.ActiveDirectoryRights)" -match 'GenericAll'
    }
}
Export-Evidence 'RecentEvents' {
    foreach ($log in 'Security','System') {
        $ids = if ($log -eq 'Security') { @(4624,4625,4648,4720,4728,4732,4740,4756,4767,4768,4769,4776,1102) } else { @(7045) }
        $eventErrors = @()
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$log;Id=$ids;StartTime=(Get-Date).AddHours(-1)} -MaxEvents 5000 -ErrorAction SilentlyContinue -ErrorVariable eventErrors)
        foreach ($err in $eventErrors) { if ($err.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw $err } }
        if ($events.Count -eq 5000) { Write-Warning "$log results reached the 5,000-event limit; older matching events may be omitted. Narrow the time range for further investigation." }
        $events | Select-Object TimeCreated,Id,LogName,Message
    }
}
Export-Evidence 'DefenderStatus' { Get-DefenderRuntimeStatus }
Invoke-Step 'Review AD CS and KRBTGT recovery requirements manually' {
    Write-Host 'Review CA/template permissions and requests. Guided mode offers one KRBTGT reset with a hidden password prompt after checking backup, replication and time since any prior reset. Audit/WhatIf do not reset passwords.'
} | Out-Null
Invoke-Step 'Review incident-response follow-up manually' {
    Write-Host 'Test DNS, Kerberos, LDAP, SYSVOL, replication, console access and scoring. Use Sysinternals/external scans. Review evidence before killing processes or deleting tasks/services/registry entries. Record incidents. No automatic reboot.'
} | Out-Null
Invoke-Step 'Check Defender installation (read-only; use -Defender to install if missing)' {
    $installation = Get-DefenderInstallationStatus
    $installation | Format-List | Out-Host
    if ($installation.RestartNeeded) {
        Write-Warning 'Defender feature servicing is pending a restart. Coordinate the restart, then run .\DC.ps1 -Defender.'
    } elseif (!$installation.Installed) {
        Write-Host 'Defender installation is missing, disabled or incomplete. Run .\DC.ps1 -Defender to check/install it and enable protection. No installation was attempted in this walkthrough.'
    }
    Write-Host 'This checks installation only; it does not verify active real-time protection.'
} | Out-Null
if ($Mode -ne 'Audit') {
    Invoke-Step 'Reset KRBTGT ONCE (asks for a password; checks replication and prevents a recent repeat reset)' {
        Write-Warning 'A single reset retains the previous KRBTGT key. It does not by itself evict attackers or complete recovery from stolen KRBTGT keys.'
        Invoke-KrbtgtRotation
    } | Out-Null
}
if ($script:CanWriteReport) {
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Get-GPOReport -All -ReportType Html -Path (Join-Path $report 'GPO.html') -Server $adServer
        $script:Results.Add([pscustomobject]@{ Step='Export domain GPO report'; Status='Completed'; Error='' })
        Write-Host '[Completed] Export domain GPO report'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Export domain GPO report'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Export domain GPO report FAILED: $($_.Exception.Message)"
    }
    try {
        $script:Results | Export-Csv -LiteralPath (Join-Path $report 'results.csv') -NoTypeInformation
        $script:Results.Add([pscustomobject]@{ Step='Save walkthrough results.csv in the protected report directory'; Status='Completed'; Error='' })
        Write-Host '[Completed] Save walkthrough results.csv in the protected report directory'
    } catch {
        $script:Results.Add([pscustomobject]@{ Step='Save walkthrough results.csv in the protected report directory'; Status='Failed'; Error=$_.Exception.Message })
        Write-Warning "Save walkthrough results.csv in the protected report directory FAILED: $($_.Exception.Message)"
    }
    Write-Host "Report directory: $report"
}
$script:Results | Format-Table -AutoSize
$pendingRestartSteps = @($script:Results | Where-Object Status -eq 'PendingRestart')
if ($pendingRestartSteps.Count) {
    Write-Warning "$($pendingRestartSteps.Count) step(s) saved settings that require a planned restart and verification. Their active runtime settings were not verified. No automatic restart was performed."
}
$failedSteps = @($script:Results | Where-Object Status -eq 'Failed')
if ($failedSteps.Count) {
    Write-Warning "Walkthrough ended with $($failedSteps.Count) failed step(s). Earlier successful changes remain applied; review the failed steps and report before retrying."
    $failedSteps | Select-Object Step,Error | Format-Table -Wrap -AutoSize
    exit 1
}
Write-Host 'Walkthrough finished with no recorded failures. Review skipped actions, backup gaps and live scoring before declaring the host ready.'
