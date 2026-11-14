@echo off
:: Verify Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [-] ERROR: Please right-click and "Run as administrator"!
    pause
    exit /b 1
)

set PA_IP=172.20.240.200
set BACKUP_FILE=C:\fw_backup.wfw

echo =================================================================
echo    MWCCDC WINDOWS WORKSTATION LOCKDOWN (PALO ALTO GUI ONLY)
echo =================================================================

:: 1. Backup existing firewall configuration for 1-second rollback
if not exist "%BACKUP_FILE%" (
    echo [*] Backing up original firewall policy to %BACKUP_FILE%...
    netsh advfirewall export "%BACKUP_FILE%"
)

:: 2. Enable Windows Firewall on all profiles & set default to BLOCK ALL
echo [*] Enabling firewall and blocking all Inbound and Outbound traffic...
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

:: 3. Disable all built-in Windows allow rules so nothing bypasses the block
echo [*] Disabling pre-existing allow rules...
netsh advfirewall firewall set rule all new enable=no

:: 4. Clean up any previous instances of our custom rules
netsh advfirewall firewall delete rule name="CCDC-ALLOW-PA-MGMT-OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="CCDC-ALLOW-DHCP-OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="CCDC-ALLOW-DHCP-IN" >nul 2>&1
netsh advfirewall firewall delete rule name="CCDC-ALLOW-ICMPv4-IN" >nul 2>&1
netsh advfirewall firewall delete rule name="CCDC-ALLOW-ICMPv4-OUT" >nul 2>&1

:: 5. Allow Outbound HTTPS (443) and SSH (22) strictly to the Palo Alto
echo [*] Allowing outbound HTTPS (443) and SSH (22) to Palo Alto (%PA_IP%)...
netsh advfirewall firewall add rule name="CCDC-ALLOW-PA-MGMT-OUT" dir=out action=allow protocol=TCP remoteip=%PA_IP% remoteport=443,22

:: 6. Allow DHCP renewals (Workstations use DHCP per MWCCDC topology)
echo [*] Allowing DHCP lease renewals...
netsh advfirewall firewall add rule name="CCDC-ALLOW-DHCP-OUT" dir=out action=allow protocol=UDP localport=68 remoteport=67
netsh advfirewall firewall add rule name="CCDC-ALLOW-DHCP-IN" dir=in action=allow protocol=UDP localport=68 remoteport=67

:: 7. Allow ICMPv4 (Ping) to comply with MWCCDC Competition Play Rule 12
echo [*] Allowing ICMPv4 (Ping) per MWCCDC Rule 12...
netsh advfirewall firewall add rule name="CCDC-ALLOW-ICMPv4-IN" dir=in action=allow protocol=icmpv4
netsh advfirewall firewall add rule name="CCDC-ALLOW-ICMPv4-OUT" dir=out action=allow protocol=icmpv4

echo.
echo [+] LOCKDOWN COMPLETE! This workstation can ONLY talk to %PA_IP% (and respond to Ping).
echo [!] To undo this lockdown at any time, run as Administrator:
echo     netsh advfirewall import "%BACKUP_FILE%"
echo =================================================================
pause
