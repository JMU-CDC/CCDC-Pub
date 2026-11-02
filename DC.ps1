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

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    $status = 'Skipped'
    $errorText = ''
    try {
        if (!$script:RunContext.ShouldProcess($Name, 'Run guided plan action')) {
            $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
        } elseif (Read-StepChoice $Name) {
            & $Action | Out-Host
            $status = 'Completed'
        }
    } catch [System.OperationCanceledException] {
        $errorText = $_.Exception.Message
    } catch {
        $status = 'Failed'
        $errorText = $_.Exception.Message
    }
    $script:Results.Add([pscustomobject]@{ Step=$Name; Status=$status; Error=$errorText })
    if ($status -eq 'Failed') { Write-Warning "$Name FAILED: $errorText. Review this before running the next action." }
    else { Write-Host "[$status] $Name" }
    return ($status -eq 'Completed')
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

function Enable-LsassAsrRule {
    foreach ($command in 'Get-MpComputerStatus','Get-MpPreference','Add-MpPreference') {
        if (!(Get-Command $command -ErrorAction SilentlyContinue)) { throw "Required Defender command is unavailable: $command" }
    }
    $status = Get-MpComputerStatus -ErrorAction Stop
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
    param([string]$Description, [string]$Path, [string]$Name, [int]$Value)
    Invoke-Step "$Description ($Name = $Value)" {
        New-Item -Path $Path -Force | Out-Null
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        if ((Get-ItemProperty -Path $Path -Name $Name).$Name -ne $Value) { throw 'Registry readback did not match.' }
    } | Out-Null
}

function Set-AllowRule {
    param([string]$Name, [string]$Protocol, [string[]]$Port, [string[]]$Address)
    $ruleName = "CCDC-AD-$Name"
    return (Invoke-Step "Allow $Protocol ports $($Port -join ',') from $($Address -join ',') [$ruleName]" {
        $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            $existing | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any
            $existing | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol $Protocol -LocalPort $Port
            $existing | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $Address
        } else {
            New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Group 'CCDC Server AD' `
                -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $Protocol `
                -LocalPort $Port -RemoteAddress $Address | Out-Null
        }
    })
}

function Export-Evidence {
    param([string]$Name, [scriptblock]$Query)
    Invoke-Step "Review/export $Name" {
        $data = & $Query
        $data | Out-Host
        if ($script:CanWriteReport) { $data | Export-Clixml -LiteralPath (Join-Path $report "$Name.xml") -Depth 6 }
    } | Out-Null
}

function Invoke-BaselineNative {
    param([string]$File,[string[]]$Arguments,[int]$MaximumExitCode=0)
    $output = @(& $File @Arguments 2>&1)
    if ($LASTEXITCODE -lt 0 -or $LASTEXITCODE -gt $MaximumExitCode) { throw "$File failed (exit $LASTEXITCODE): $($output -join ' ')" }
    return $output
}

function Get-ServiceBaseline {
    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId)
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine)
    $issues = New-Object 'System.Collections.Generic.List[object]'
    $endpoints = New-Object 'System.Collections.Generic.List[object]'
    $hints = @{21='FTP';22='SSH';25='SMTP';53='DNS';80='HTTP';110='POP3';123='NTP';143='IMAP';389='LDAP';443='HTTPS';445='SMB';636='LDAPS';1433='SQL';3389='RDP';5985='WinRM HTTP';5986='WinRM HTTPS';8000='Possible Splunk web';8089='Possible Splunk management';9997='Possible Splunk receiver'}
    foreach ($protocol in 'TCP','UDP') {
        try {
            $items = if ($protocol -eq 'TCP') { @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } else { @(Get-NetUDPEndpoint -ErrorAction Stop) }
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
        try { $shares = @(Get-SmbShare -ErrorAction Stop | Select-Object Name,Path,Description,Special,ScopeName) }
        catch { $issues.Add([pscustomobject]@{Source='SMB shares';Error=$_.Exception.Message}) }
    }
    $features = @()
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try { $features = @(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed | Select-Object Name,DisplayName) }
        catch { $issues.Add([pscustomobject]@{Source='Windows roles/features';Error=$_.Exception.Message}) }
    }
    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
    $sites = ''; $vdirs = ''; $roots = @()
    if (Test-Path -LiteralPath $appcmd) {
        try {
            $sites = (Invoke-BaselineNative $appcmd @('list','site','/xml')) -join [Environment]::NewLine
            $vdirs = (Invoke-BaselineNative $appcmd @('list','vdir','/xml')) -join [Environment]::NewLine
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
        while ($true) {
            $answer = Read-Host 'Press Enter to back up, or n then Enter to skip'
            if ($null -eq $answer) { throw 'Interactive input is unavailable.' }
            if ($answer -eq '' -or $answer.Trim() -ieq 'n') { break }
        }
        if ($answer -eq '') {
            try { & $Action | Out-Host; $state='Completed' }
            catch { $state='Failed'; $detail=$_.Exception.Message; Write-Warning "$Name failed: $detail" }
        }
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
            Invoke-BaselineBackup "AD system state to $SystemStateBackupTarget (potentially lengthy; requires Windows Server Backup)" 'System-state backup' { Backup-BaselineSystemState $SystemStateBackupTarget }
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
        $script:BaselineResults.Add([pscustomobject]@{Name=$issue.Source;Kind='Discovery';Status='Failed';Detail=$issue.Error})
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

$computer = Get-CimInstance Win32_ComputerSystem
if ($computer.DomainRole -notin 4, 5) { throw 'Run this AD plan on a domain controller.' }
Import-Module ActiveDirectory
Import-Module NetSecurity
$adServer = $env:COMPUTERNAME
$domain = Get-ADDomain -Server $adServer
$administrator = Get-ADUser -Identity "$($domain.DomainSID.Value)-500" -Server $adServer
$report = Join-Path $ReportRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
Write-Host 'Guided AD plan: Enter runs one action; n skips it; Ctrl+C stops the walkthrough.' -ForegroundColor Cyan
Write-Host 'Discover and back up services before hardening. Configuration exports are not a server image; AD recovery needs system state. Use -SystemStateBackupTarget for an optional system-state backup.'
Write-Host "Domain: $($domain.DNSRoot). Main administrator: $($administrator.SamAccountName)."

Write-Host "`n0. Discover services, then back up before hardening" -ForegroundColor Cyan
$script:InitialServiceInventory = $null
Invoke-Step 'Discover installed services/listeners/sites BEFORE any password or hardening changes' {
    $script:InitialServiceInventory = Get-ServiceBaseline
    $script:InitialServiceInventory.Endpoints | Sort-Object Port,Protocol | Format-Table -Wrap -AutoSize | Out-Host
    $script:InitialServiceInventory.Features | Format-Table -AutoSize | Out-Host
    $script:InitialServiceInventory.Shares | Format-Table -AutoSize | Out-Host
    if ($script:InitialServiceInventory.IisSitesXml) { Write-Host $script:InitialServiceInventory.IisSitesXml }
    foreach ($issue in $script:InitialServiceInventory.Issues) { Write-Warning "$($issue.Source): $($issue.Error)" }
} | Out-Null
Invoke-Step 'Set timestamped PowerShell and child CMD prompts for this session' {
    function global:prompt {
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')] | PS $(Get-Location)`n--> "
    }
    $env:PROMPT = '$D$S$T$H$H$H$S$B$S$P$_--$G'
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')] Shell timestamps enabled."
} | Out-Null

$script:CanWriteReport = Invoke-Step "Create protected report directory: $report" {
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
}
Invoke-Step 'Back up discovered services BEFORE password or hardening changes (each backup has its own Enter/n prompt)' {
    if ($null -eq $script:InitialServiceInventory) { throw 'Service discovery was skipped or failed. Rerun discovery before attempting service backups.' }
    $options = @{ Inventory=$script:InitialServiceInventory; OutputDirectory=(Join-Path $report 'ServiceBaseline'); DiscoveryOnly=($Mode -eq 'Audit'); NoReport=(!$script:CanWriteReport) }
    if ($SystemStateBackupTarget) { $options.SystemStateBackupTarget=$SystemStateBackupTarget }
    $baselineResult = Invoke-InitialServiceBackups @options
    if ($baselineResult.FailedCount -gt 0) { throw 'Service discovery/backups have failures. Review ServiceBaseline/backup-status.csv before proceeding; some recovery gaps may remain.' }
} | Out-Null
Export-Evidence 'Services-Before' { Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, StartName, PathName }
if ($script:CanWriteReport) {
    Invoke-Step 'Export original firewall policy' { Invoke-Native netsh.exe @('advfirewall','export',(Join-Path $report 'firewall-before.wfw')) } | Out-Null
    Invoke-Step 'Export original audit policy' { Invoke-Native auditpol.exe @('/backup',"/file:$(Join-Path $report 'audit-before.csv')") } | Out-Null
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
    Invoke-Step 'Disable the domain Guest account' {
        $guest = "$($domain.DomainSID.Value)-501"
        Disable-ADAccount -Identity $guest -Server $adServer
        if ((Get-ADUser -Identity $guest -Server $adServer).Enabled) { throw 'Guest is still enabled.' }
    } | Out-Null
    Set-RegistryDword 'Restrict anonymous access' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1
    Invoke-Step 'Set DOMAIN minimum password length to 12 characters' {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -MinPasswordLength 12 -Server $adServer
    } | Out-Null
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
    Invoke-Step 'Remove the current operator screensaver executable setting' {
        if (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue) {
            Remove-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE
        }
    } | Out-Null
    foreach ($stickyKeysTarget in @(
        @{ Name = 'current operator'; Path = 'HKCU:\Control Panel\Accessibility\StickyKeys' },
        @{ Name = 'sign-in screen (.DEFAULT)'; Path = 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys' }
    )) {
        Invoke-Step "Disable Sticky Keys and the five-Shift shortcut for $($stickyKeysTarget.Name) (saved setting; verify after next sign-in/restart)" {
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
        } | Out-Null
    }
    Invoke-Step 'Disable SMBv1 on the SMB server' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } | Out-Null
    Invoke-Step 'Require SMB SERVER signing' { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force } | Out-Null
    Invoke-Step 'Require SMB CLIENT signing' { Set-SmbClientConfiguration -RequireSecuritySignature $true -Force } | Out-Null
    Invoke-Step 'Restrict network-logon access to Service Control Manager (PsExec-style service creation; also blocks legitimate remote service management; requires protected backup directory)' {
        Protect-ScManagerNetworkAccess
    } | Out-Null
    Set-RegistryDword 'Disable LLMNR' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    foreach ($nic in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True') {
        Invoke-Step "Disable NetBIOS over TCP/IP on adapter: $($nic.Description)" {
            $outcome = Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2}
            if ($outcome.ReturnValue -notin 0,1) { throw "NetBIOS change failed: $($outcome.ReturnValue)" }
            if ($outcome.ReturnValue -eq 1) { Write-Warning 'NetBIOS change needs a restart.' }
        } | Out-Null
    }
    foreach ($tunnel in 'teredo','6to4','isatap') {
        Invoke-Step "Disable IPv6 $tunnel tunnel (native IPv6 stays enabled)" {
            $arguments = if ($tunnel -eq 'teredo') { @('interface','teredo','set','state','disabled') }
                else { @('interface','ipv6',$tunnel,'set','state','state=disabled') }
            Invoke-Native netsh.exe $arguments
        } | Out-Null
    }
    foreach ($serviceName in 'Spooler','RemoteRegistry') {
        Invoke-Step "Stop service $serviceName" {
            Stop-Service -Name $serviceName -Force
            if ((Get-Service $serviceName).Status -ne 'Stopped') { throw 'Service did not stop.' }
        } | Out-Null
        Invoke-Step "Disable service $serviceName startup" {
            Set-Service -Name $serviceName -StartupType Disabled
        } | Out-Null
    }
    Invoke-Step 'Set WinRM startup to Automatic and start it (AD WinRM is scored; listeners/authentication are verified separately)' {
        Set-Service -Name WinRM -StartupType Automatic
        Start-Service -Name WinRM
        if ((Get-Service -Name WinRM).Status -ne 'Running') { throw 'WinRM did not start.' }
    } | Out-Null

    Write-Host "`n3. Firewall and connections" -ForegroundColor Cyan
    $tcpReady = Set-AllowRule 'Domain-TCP' TCP @('53','88','135','389','445','464','636','3268','3269','49152-65535') $DomainClientAddress
    $udpReady = Set-AllowRule 'Domain-UDP' UDP @('53','88','123','389','464') $DomainClientAddress
    foreach ($port in $ScoredTcpPort) { Set-AllowRule "Scored-TCP-$port" TCP @("$port") @('Any') | Out-Null }
    foreach ($port in $ScoredUdpPort) { Set-AllowRule "Scored-UDP-$port" UDP @("$port") @('Any') | Out-Null }
    Invoke-Step 'Allow inbound ICMPv4 echo requests for reachability/scoring checks' {
        if (!(Get-NetFirewallRule -Name CCDC-AD-ICMP -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name CCDC-AD-ICMP -DisplayName CCDC-AD-ICMP -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
        }
    } | Out-Null
    Invoke-Step 'Enable Windows Firewall on all profiles after preparing AD allow rules' {
        if (!$tcpReady -or !$udpReady) {
            throw 'Required AD allow rules were skipped or failed. Firewall activation was not changed; review existing rules manually.'
        }
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    } | Out-Null
    Invoke-Step 'Block unmatched inbound traffic and allow outbound traffic' {
        if (!$tcpReady -or !$udpReady) {
            throw 'Required AD allow rules were skipped or failed. Default policy was not changed; review existing rules manually.'
        }
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow
    } | Out-Null
    Invoke-Step 'Enable firewall allowed/blocked traffic logging (32 MB per profile)' {
        Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 32767
    } | Out-Null
    Export-Evidence 'Connections' { Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess }

    Write-Host "`n4. Audit and logging" -ForegroundColor Cyan
    Set-RegistryDword 'Use advanced audit subcategories instead of legacy audit policy' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
    Invoke-Step 'Enable success/failure auditing for all categories' { Invoke-Native auditpol.exe @('/set','/category:*','/success:enable','/failure:enable') } | Out-Null
    Set-RegistryDword 'Enable PowerShell script block logging' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    Invoke-Step 'Enable PowerShell module logging for all modules' {
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        New-Item -Path "$key\ModuleNames" -Force | Out-Null
        New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
    } | Out-Null
    Invoke-Step 'Enable PowerShell transcription to the protected report directory' {
        if (!$script:CanWriteReport) { throw 'Protected report directory was skipped or failed; transcription was not enabled.' }
        $transcripts = Join-Path $report 'Transcripts'
        New-Item -ItemType Directory -Path $transcripts -Force | Out-Null
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name EnableTranscripting -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name OutputDirectory -Value $transcripts -PropertyType String -Force | Out-Null
    } | Out-Null
    Set-RegistryDword 'Include command lines in process creation events' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Set-RegistryDword 'Enable UAC (may require a later reboot)' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    Set-RegistryDword 'Require administrator consent on the secure desktop' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
    Invoke-Step 'Enable Microsoft Defender real-time protection and verify active status' {
        foreach ($command in 'Get-MpComputerStatus','Set-MpPreference') {
            if (!(Get-Command $command -ErrorAction SilentlyContinue)) {
                throw 'Defender commands are unavailable. Verify protection in the installed antivirus product or install/configure Defender separately.'
            }
        }
        $before = Get-MpComputerStatus -ErrorAction Stop
        if ($before.AMRunningMode -match 'Passive|EDR Block') {
            throw "Defender is in $($before.AMRunningMode) mode. Verify real-time protection in the primary antivirus product; active mode was not forced."
        }
        if (!$before.AMServiceEnabled) {
            throw 'Defender antivirus service is not running. Review service status and applied policy, then retry.'
        }
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        $status = Get-MpComputerStatus -ErrorAction Stop
        $status | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled
        if (!$status.AMServiceEnabled -or !$status.AntivirusEnabled -or !$status.RealTimeProtectionEnabled) {
            throw 'Defender real-time protection is not active after the request. Review applied policy, tamper protection, and antivirus/service configuration; no protection controls were bypassed.'
        }
    } | Out-Null
    Invoke-Step 'Update Microsoft Defender signatures (if no Internet, type n to skip; an internal update source also works)' { Update-MpSignature } | Out-Null
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
Export-Evidence 'Services-After' { Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName }
Export-Evidence 'ListeningPorts' { Get-NetTCPConnection -State Listen | Select-Object LocalPort,OwningProcess | Sort-Object LocalPort }
Export-Evidence 'Processes' { Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine }
Export-Evidence 'Tasks' { Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Actions,Principal,Triggers }
Export-Evidence 'StartupRegistry' {
    foreach ($path in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon')) {
        if (Test-Path $path) { Get-ItemProperty $path }
    }
}
Export-Evidence 'WMI-Persistence' {
    foreach ($class in '__EventFilter','__EventConsumer','__FilterToConsumerBinding') { Get-CimInstance -Namespace root/subscription -ClassName $class }
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
Export-Evidence 'DefenderStatus' { Get-MpComputerStatus }
Invoke-Step 'Review AD CS and KRBTGT recovery requirements manually' {
    Write-Host 'Review CA/template permissions and requests. Coordinate KRBTGT resets with replication and maximum ticket lifetime (normally 10 hours). No KRBTGT password is changed here.'
} | Out-Null
Invoke-Step 'Review incident-response follow-up manually' {
    Write-Host 'Test DNS, Kerberos, LDAP, SYSVOL, replication, console access and scoring. Use Sysinternals/external scans. Review evidence before killing processes or deleting tasks/services/registry entries. Record incidents. No automatic reboot.'
} | Out-Null
if ($script:CanWriteReport) {
    Invoke-Step 'Export domain GPO report' {
        Import-Module GroupPolicy
        Get-GPOReport -All -ReportType Html -Path (Join-Path $report 'GPO.html') -Server $adServer
    } | Out-Null
    Invoke-Step 'Save walkthrough results.csv in the protected report directory' {
        $script:Results | Export-Csv -LiteralPath (Join-Path $report 'results.csv') -NoTypeInformation
    } | Out-Null
    Write-Host "Report directory: $report"
}
$script:Results | Format-Table -AutoSize
if (@($script:Results | Where-Object Status -eq 'Failed').Count) { throw 'Some actions failed. Review the summary; the plan is not fully complete.' }
