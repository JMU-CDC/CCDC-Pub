

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] This script must be executed in an elevated PowerShell session (Run as Administrator)." -ForegroundColor Red
    Exit
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   MWCCDC 2019 MSSQL INTERACTIVE HARDENING   " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan


function Get-SecureInputPassword {
    param (
        [string]$PromptTitle
    )
    $valid = $false$plainText = ""
    $secPass =$null

    while (-not $valid) {
        Write-Host "`n[*] $PromptTitle" -ForegroundColor Yellow
        $secPass = Read-Host -Prompt "Enter new password" -AsSecureString
        $secPassConfirm = Read-Host -Prompt "Confirm new password" -AsSecureString

        $bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
        $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr1)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)

        $bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPassConfirm)
        $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)

        if ($plain1 -ne $plain2) {
            Write-Host "[!] Passwords do not match. Please try again." -ForegroundColor Red
            continue
        }

        
        if ($plain1.Length -ge 12 -and $plain1 -match "[A-Z]" -and $plain1 -match "[a-z]" -and $plain1 -match "[0-9]" -and $plain1 -match "[\W_]") {
            $valid = $true
            $plainText = $plain1
        } else {
            Write-Host "[!] Password does not meet requirements:" -ForegroundColor Red
            Write-Host "    - At least 12 characters" -ForegroundColor DarkYellow
            Write-Host "    - At least one uppercase letter, one lowercase letter, one number, and one special character" -ForegroundColor DarkYellow
        }
    }

    return [PSCustomObject]@{
        SecureString = $secPass
        PlainText    = $plainText
    }
}


$OSCredentials  = Get-SecureInputPassword -PromptTitle "Set password for Local Windows Accounts (sysadmin, Administrator)"
$SqlCredentials = Get-SecureInputPassword -PromptTitle "Set password for SQL Server 'sa' Account"


Write-Host "`n[*] Updating local Windows user accounts..." -ForegroundColor Yellow
$OSUsers = @("sysadmin", "Administrator")
foreach ($u in$OSUsers) {
    if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name $u -Password$OSCredentials.SecureString
        Set-LocalUser -Name $u -PasswordNeverExpires$true
        Write-Host "[+] Local password rotated for: $u" -ForegroundColor Green
    }
}


Write-Host "`n[*] Purging accessibility and IFEO debugger hijacking..." -ForegroundColor Yellow
$AccessibilityApps = @("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "DisplaySwitch.exe")
foreach ($app in $AccessibilityApps) {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$app"
    if (Test-Path $regPath) {
        $debugger = (Get-ItemProperty -Path $regPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Remove-ItemProperty -Path $regPath -Name "Debugger" -Force
            Write-Host "[ALERT] Removed IFEO backdoor on $app: $debugger" -ForegroundColor Red
        }
    }
}
Write-Host "[+] Accessibility registry keys audited." -ForegroundColor Green


Write-Host "`n[*] Hardening MSSQL Database Instance..." -ForegroundColor Yellow


$EscapedSqlPass =$SqlCredentials.PlainText.Replace("'", "''")

$sqlQuery = @"
-- Change SA Password and verify account status
ALTER LOGIN [sa] WITH PASSWORD = '$EscapedSqlPass', CHECK_EXPIRATION = OFF, CHECK_POLICY = ON;
ALTER LOGIN [sa] ENABLE;

-- Disable features exploited for remote command execution
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE WITH OVERRIDE;
EXEC sp_configure 'xp_cmdshell', 0;
EXEC sp_configure 'Ole Automation Procedures', 0;
EXEC sp_configure 'clr enabled', 0;
EXEC sp_configure 'Database Mail XPs', 0;
EXEC sp_configure 'remote access', 0;
RECONFIGURE WITH OVERRIDE;

-- Revoke dangerous procedures from public role
REVOKE EXECUTE ON master..xp_cmdshell FROM [public];
REVOKE EXECUTE ON master..xp_dirtree FROM [public];
REVOKE EXECUTE ON master..xp_fileexist FROM [public];
"@

try {
    
    $result = sqlcmd -E -S localhost -Q$sqlQuery -b
    Write-Host "[+] MSSQL instance successfully hardened and 'sa' password rotated." -ForegroundColor Green
} catch {
    Write-Host "[-] Error executing sqlcmd queries. Ensure SQL Server service (MSSQLSERVER) is running." -ForegroundColor Red
}


$OSCredentials.PlainText =$null
$SqlCredentials.PlainText =$null
$EscapedSqlPass =$null


Write-Host "`n[*] Applying host firewall rules for scored services..." -ForegroundColor Yellow


Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True


$ScoredRules = @(
    @{ Name = "CCDC-MSSQL-In"; Port = 1433; Protocol = "TCP" },
    @{ Name = "CCDC-RDP-In";   Port = 3389; Protocol = "TCP" },
    @{ Name = "CCDC-SMB-In";   Port = 445;  Protocol = "TCP" }
)

foreach ($rule in $ScoredRules) {
    if (-not (Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $rule.Name -DisplayName $rule.Name `
            -Direction Inbound -Protocol $rule.Protocol -LocalPort$rule.Port `
            -Action Allow | Out-Null
        Write-Host "[+] Created inbound firewall rule: $($rule.Name) ($($rule.Port)/$($rule.Protocol))" -ForegroundColor Green
    } else {
        Set-NetFirewallRule -Name $rule.Name -Action Allow -Enabled True | Out-Null
        Write-Host "[*] Verified inbound firewall rule: $($rule.Name)" -ForegroundColor Green
    }
}


Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -ErrorAction SilentlyContinue
Write-Host "[+] ICMPv4 Echo Request rule enabled." -ForegroundColor Green


Write-Host "`n[*] Validating Scored SOP SMB Shares..." -ForegroundColor Yellow
$shares = Get-SmbShare \vert{} Where-Object {$_.Name -notmatch "ADMIN\$|C\$|IPC\$" }

if ($shares) {
    foreach ($sh in$shares) {
        Write-Host "[+] Active SMB Share Detected: $($sh.Name) -> Path: $($sh.Path)" -ForegroundColor Cyan
        $sopFiles = Get-ChildItem -Path$sh.Path -File -ErrorAction SilentlyContinue
        if ($sopFiles) {
            Write-Host "    Found $(($sopFiles | Measure-Object).Count)
