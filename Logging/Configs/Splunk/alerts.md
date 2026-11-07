* **Account Backdoors & Manipulation** (Created, deleted, password reset, log cleared):
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

---


* **Privilege Escalation & Unauthorized Commands**:
  ```spl
  index=velociraptor Artifact="Custom.Linux.Events.All" ("sudo:" OR "useradd" OR "NOPASSWD" OR "visudo")
  | table _time Hostname AppName Message
  ```

* **SSH Brute Force**:
  ```spl
  index=velociraptor Artifact="Custom.Linux.Events.All" AppName=sshd ("Failed password" OR "authentication failure")
  | stats count by Hostname Message
  | where count > 5
  ```