* **Account Backdoors & Manipulation**
  ```spl
  index=velociraptor EventID IN (4720, 4722, 4724, 4726, 4728, 4732, 4738, 4756, 1102)
  | table _time Computer EventID EventData.SubjectUserName EventData.TargetUserName
  ```

* **Persistence: New Service or Scheduled Task**:
  ```spl
  index=velociraptor EventID IN (7045, 4697, 4698)
  | table _time Computer EventID EventData.ServiceName EventData.ImagePath EventData.TaskName
  ```

* **Malicious PowerShell Script Blocks** (Event ID 4104):
  ```spl
  index=velociraptor EventID=4104 ("DownloadString" OR "IEX" OR "-enc" OR "bypass" OR "Invoke-ReflectivePEInjection")
  | table _time Computer EventData.ScriptBlockText
  ```

* **RDP / Windows Brute Force**:
  ```spl
  index=velociraptor EventID=4625
  | stats count by Computer EventData.IpAddress EventData.TargetUserName
  | where count > 5
  ```

* **Defender Threat Detections**:
  ```spl
  index=velociraptor Channel="*Defender*" EventID IN (1116, 1117)
  | table _time Computer EventID EventData
  ```

* **Suspicious Process Creation / Credential Dumping**:
  ```spl
  index=velociraptor (EventID=4688 OR Artifact="Windows.Events.ProcessCreation") ("vssadmin" OR "mimikatz" OR "procdump" OR "reg save" OR "ntdsutil" OR "certutil -urlcache")
  | table _time Computer CommandLine ParentCommandLine SubjectUserName
  ```

* **Defender Tampering / Disabled**:
  ```spl
  index=velociraptor Channel="*Defender*" EventID IN (5001, 5007)
  | table _time Computer EventID EventData
  ```

* **RDP Session Hijacking / Reconnect**:
  ```spl
  index=velociraptor Channel="*LocalSessionManager*" EventID IN (24, 25)
  | table _time Computer EventID UserData.User UserData.Address
  ```

---


* **Privilege Escalation & Unauthorized Commands**:
  ```spl
  index=velociraptor Artifact="Custom.Linux.Events.All" ("sudo:" OR "useradd" OR "NOPASSWD" OR "visudo")
  | table _time Hostname AppName Message
  ```

* **SSH Brute Force**:
  ```spl
  index=velociraptor Artifact="Custom.Linux.Events.All" AppName=sshd ("Failed password" OR "authentication failure")
  | rex field=Message "from (?<src_ip>\S+)"
  | stats count by Hostname, src_ip
  | where count > 5
  ```

* **Successful Root Login via SSH**:
  ```spl
  index=velociraptor Artifact="Custom.Linux.Events.All" AppName=sshd "Accepted" "for root"
  | rex field=Message "from (?<src_ip>\S+)"
  | table _time Hostname src_ip Message
  ```

* **Interactive `su` to Root**:
  ```spl
  index=velociraptor Artifact="Custom.Linux.Events.All" AppName=su "Successful su for root"
  | table _time Hostname Message
  ```

---

### LOW PRIORITY ALERTS DO ONLY WHEN DOWNTIME

* **Endpoint Stopped Reporting (Agent Down / Offline)**:
  ```spl
  index=velociraptor Artifact="Generic.Client.Stats"
  | stats latest(_time) as last_seen by Hostname
  | eval minutes_ago=(now() - last_seen)/60
  | where minutes_ago > 5
  ```

* **Successful RDP Logins (Windows)**:
  ```spl
  index=velociraptor EventID=4624 EventData.LogonType=10
  | table _time Computer EventData.TargetUserName EventData.IpAddress
  ```

* **System Event Log Cleared (Windows)**:
  ```spl
  index=velociraptor Channel="System" EventID=104
  | table _time Computer
  ```

* **Software Installed or Removed (Linux)**:
  ```spl
  index=velociraptor Artifact="Custom.Linux.Events.All" ("apt" OR "yum" OR "dnf" OR "dpkg" OR "rpm")
  | table _time Hostname AppName Message
  ```