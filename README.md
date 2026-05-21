# 🛡️ MITRE ATT&CK SOC Home Lab — Splunk Threat Detection

![Splunk](https://img.shields.io/badge/Splunk-Enterprise%209.x-000000?style=for-the-badge&logo=splunk&logoColor=green)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20|%20T1110.001%20|%20T1110.003-red?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows%20Server-2022-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![VirtualBox](https://img.shields.io/badge/Oracle-VirtualBox-183A61?style=for-the-badge&logo=virtualbox&logoColor=white)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)

> A fully functional **Security Operations Centre (SOC) home lab** built from scratch using Oracle VirtualBox, Windows Server 2022, and Splunk Enterprise. Simulates real-world brute force and password spraying attacks mapped to the **MITRE ATT&CK framework**, with automated detection alerts, live dashboard, and full SOC investigation workflow.

---

## 📸 Dashboard Preview

| Panel | Data |
|-------|------|
| Total Events (24h) | 24,126 |
| Failed Logins — T1110 | 190 |
| CRITICAL Detections | WIN-00LIPAHPR97: 32 attempts · WIN-1NA69C5OMJR: 26 attempts |
| Hosts Monitored | 4 |
| Alerts Configured | 3 (T1110, T1110.003, T1110.004) |

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Architecture](#-architecture)
- [Tools & Technologies](#-tools--technologies)
- [Lab Setup](#-lab-setup)
- [Firewall Configuration](#-firewall-configuration)
- [Splunk Universal Forwarder Setup](#-splunk-universal-forwarder-setup)
- [MITRE ATT&CK Detection Rules](#-mitre-attck-detection-rules)
- [Attack Simulation](#-attack-simulation)
- [SOC Dashboard](#-soc-dashboard)
- [Key Findings](#-key-findings)
- [SPL Query Reference](#-spl-query-reference)
- [Challenges & Resolutions](#-challenges--resolutions)
- [Skills Demonstrated](#-skills-demonstrated)

---

## 🔍 Project Overview

This project demonstrates a complete **blue team detection workflow**:

1. Built a virtualised Windows Server environment with 4 monitored hosts
2. Installed and configured **Splunk Universal Forwarders** on each VM
3. Forwarded **Windows Event Logs** and **Performance Monitor** data to Splunk Enterprise
4. Created **MITRE ATT&CK-aligned detection alerts** for brute force techniques
5. Simulated **password spraying attacks** using PowerShell scripts
6. Investigated detections using **Splunk SPL queries**
7. Built a **live 8-panel SOC dashboard** with auto-refresh and email alerting


---

## 🛠️ Tools & Technologies

| Tool | Version | Purpose |
|------|---------|---------|
| Oracle VirtualBox | Latest | Hypervisor for Windows Server VMs |
| Windows Server | 2022 | Guest OS on VMs |
| Windows 11 | — | Host OS running Splunk Enterprise |
| Splunk Enterprise | 9.x | SIEM — ingestion, search, alerting, dashboard |
| Splunk Universal Forwarder | 9.x | Log forwarding agent installed on each VM |
| PowerShell | 5.1+ | Attack simulation scripts |
| MITRE ATT&CK | v14 | Threat intelligence and detection framework |

---

## 🔧 Lab Setup

### Step 1 — VirtualBox Network Configuration

> ⚠️ **Critical:** VMs must use **Bridged Adapter** mode — NAT mode will prevent host-VM communication.
>
> Verify connectivity from VM to host:
```cmd
ping 192.168.1.67
```
Expected: 4 replies, 0% packet loss.

---

### Step 2 — Enable Splunk Receiving on Host

In Splunk Web on the host machine:



---

### Step 3 — Install Splunk Universal Forwarder on Each VM

Download from: https://www.splunk.com/en_us/download/universal-forwarder.html

Select **Windows 64-bit** → run the `.msi` as Administrator:


Default install path:


**Method 2 — CMD as Administrator:**
```cmd
netsh advfirewall firewall add rule ^
  name="Splunk UF Outbound 9997" ^
  dir=out ^
  action=allow ^
  protocol=TCP ^
  remoteport=9997 ^
  program="C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe"
```

### On Host Machine — Inbound Rules

```cmd
netsh advfirewall firewall add rule name="Splunk-9997-In" protocol=TCP dir=in localport=9997 action=allow

netsh advfirewall firewall add rule name="Allow ICMPv4-In" protocol=icmpv4:8,any dir=in action=allow
```

---

## 📡 Splunk Universal Forwarder Setup

Navigate to the bin directory first on each VM:

```cmd
cd "C:\Program Files\SplunkUniversalForwarder\bin"
```

### Check forwarder status
```cmd
splunk status
```

### Add the forward server
```cmd
splunk add forward-server 192.168.1.67:9997 -auth admin:yourpassword
```

### Verify it was added
```cmd
splunk list forward-server -auth admin:yourpassword
```

### inputs.conf — what logs to forward

Path: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
index = main
disabled = 0
start_from = oldest
current_only = 0

[WinEventLog://System]
index = main
disabled = 0
start_from = oldest
current_only = 0

[WinEventLog://Application]
index = main
disabled = 0
start_from = oldest
current_only = 0

[perfmon://CPU]
object = Processor
counters = % Processor Time
instances = _Total
interval = 30
index = main
disabled = 0

[perfmon://Memory]
object = Memory
counters = Available Bytes
interval = 30
index = main
disabled = 0

[perfmon://Network]
object = Network Interface
counters = Bytes Sent/sec; Bytes Received/sec
interval = 30
index = main
disabled = 0
```

### outputs.conf — where to send logs

Path: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.1.67:9997

[tcpout-server://192.168.1.67:9997]
```

### Restart the forwarder
```cmd
splunk restart
```

### Verify on Splunk Enterprise host
```spl
index=* | stats count by host | sort -count
```

---

## 🎯 MITRE ATT&CK Detection Rules

### Coverage

| Tactic | Technique | Sub-Technique | Description |
|--------|-----------|---------------|-------------|
| TA0006 Credential Access | T1110 | — | Brute Force |
| TA0006 Credential Access | T1110 | T1110.001 | Password Guessing |
| TA0006 Credential Access | T1110 | T1110.003 | Password Spraying |
| TA0006 Credential Access | T1110 | T1110.004 | Credential Stuffing |

### Windows Event Codes Monitored

| EventCode | Description | MITRE Relevance |
|-----------|-------------|-----------------|
| 4625 | Failed logon | T1110 — primary indicator |
| 4624 | Successful logon | Post-attack success check |
| 4672 | Admin privilege assigned | Privilege escalation |
| 4648 | Explicit credential use | T1110.004 |
| 5379 | Credential Manager read | Baseline activity |

---

### Alert 1 — T1110 Brute Force Detection

```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by host, Account_Name
| where count >= 5
| sort -count
```
**Schedule:** Weekly · **Trigger:** Results > 0 · **Action:** Send email

---

### Alert 2 — T1110.003 Password Spraying Detection

```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=5m
| stats dc(Account_Name) as unique_accounts,
        count by _time, host
| where unique_accounts >= 3 AND count >= 10
| eval Severity=case(
    count >= 20, "CRITICAL",
    count >= 15, "HIGH",
    count >= 10, "MEDIUM",
    true(),      "LOW")
| eval MITRE="T1110.003 - Password Spraying"
```
**Schedule:** Every 15 minutes · **Trigger:** Results > 0 · **Action:** Send email

---

### Alert 3 — T1110.004 Credential Stuffing Detection

```spl
index=* sourcetype=WinEventLog:Security EventCode=4648
| stats count by host, Account_Name, Target_Server
| where count >= 5
| eval MITRE="T1110.004 - Credential Stuffing"
```
**Schedule:** Every 15 minutes · **Trigger:** Results > 0 · **Action:** Send email

---

## ⚔️ Attack Simulation

### Brute Force — T1110.001

Run in **PowerShell as Administrator** on any VM:

```powershell
$target = "127.0.0.1"
$user = "Administrator"
$wrongPassword = "FakePassword999"

for ($i = 1; $i -le 10; $i++) {
    $securePass = ConvertTo-SecureString $wrongPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($user, $securePass)
    try {
        Invoke-Command -ComputerName $target -Credential $cred `
        -ScriptBlock { whoami } -ErrorAction Stop
    } catch {
        Write-Host "Attempt $i - Failed login recorded (EventCode 4625)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 1
}
Write-Host "Simulation complete - Check Splunk for EventCode 4625" -ForegroundColor Green
```

---

### Password Spraying — T1110.003

```powershell
$target = "127.0.0.1"
$fakeUsers = @("admin", "user1", "testuser", "john.doe", "svcaccount", "backup")
$wrongPassword = "Summer2024!"

foreach ($user in $fakeUsers) {
    $securePass = ConvertTo-SecureString $wrongPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($user, $securePass)
    try {
        Invoke-Command -ComputerName $target -Credential $cred `
        -ScriptBlock { whoami } -ErrorAction Stop
    } catch {
        Write-Host "Failed login: $user" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}
Write-Host "Spraying complete - 6 accounts targeted" -ForegroundColor Yellow
```

### Verify in Splunk

```spl
index=* sourcetype=WinEventLog:Security EventCode=4625 earliest=-15m
| stats count by host, Account_Name
| sort -count
```

---

## 📊 SOC Dashboard

### 8-Panel Layout

### Panel Queries

**Total Events (24h)**
```spl
index=* earliest=-24h | stats count
```

**Failed Logins T1110**
```spl
index=* sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h | stats count
```

**Total Failed Logins**
```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count as "Total_Failed_Logins"
```

**Failed Logins by Host — Bar Chart**
```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count as Failed_Attempts by host
| sort -Failed_Attempts
```

**Event Volume by Host — Bar Chart**
```spl
index=* earliest=-24h | stats count by host | sort -count
```

**MITRE T1110.003 Detections — Table**
```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=5m
| stats dc(Account_Name) as unique_accounts, count by _time, host
| where unique_accounts >= 3 AND count >= 10
| eval Severity=case(count>=20,"CRITICAL",count>=15,"HIGH",count>=10,"MEDIUM",true(),"LOW")
| eval MITRE="T1110.003 - Password Spraying"
| table _time, host, unique_accounts, count, Severity, MITRE
| sort -count
```

**Failed Logins 10-min Windows — Table**
```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=10m
| stats count as Failed_Attempts, dc(Account_Name) as Unique_Accounts by _time, host
| eval Severity=case(
    Failed_Attempts>=20,"CRITICAL",
    Failed_Attempts>=10,"HIGH",
    Failed_Attempts>=5,"MEDIUM",
    true(),"LOW")
| eval MITRE=case(
    Unique_Accounts>=3,"T1110.003 - Password Spraying",
    true(),"T1110.001 - Password Guessing")
| table _time, host, Failed_Attempts, Unique_Accounts, Severity, MITRE
| sort -Failed_Attempts
```

**Top Security Event Codes — Pie Chart**
```spl
index=* sourcetype=WinEventLog:Security earliest=-24h | top limit=8 EventCode
```

**Event Timeline by Host — Line Chart**
```spl
index=* earliest=-24h | timechart span=1h count by host
```

---

## 🔎 Key Findings

### Detection Results

| Time | Host | Attempts | Unique Accounts | Severity | Technique |
|------|------|----------|-----------------|----------|-----------|
| 15:50 | WIN-00LIPAHPR97 | 32 | 8 | **CRITICAL** | T1110.003 |
| 15:55 | WIN-1NA69C5OMJR | 26 | 3 | **CRITICAL** | T1110.003 |
| 15:20 | WIN-1NA69C5OMJR | 20 | 2 | **CRITICAL** | T1110.001 |
| 16:10 | WIN-00LIPAHPR97 | 20 | 2 | **CRITICAL** | T1110.001 |
| 15:50 | WIN-JLT4FJU7M6R | 18 | 9 | HIGH | T1110.003 |
| 15:40 | WIN-1NA69C5OMJR | 12 | 7 | HIGH | T1110.003 |

### Most Targeted Accounts

| Account | Failed Attempts | Assessment |
|---------|----------------|------------|
| — (anonymous) | 167 | High — network-based attack |
| Administrator | 150 | High — privileged account targeted |
| user1 / testuser / svcaccount | 6 each | Spray simulation accounts |
| john.doe / backup / admin | 6 each | Spray simulation accounts |

### ✅ Verdict — No Credential Compromise Confirmed

No successful logins (EventCode 4624) were recorded for targeted accounts post-attack.

---

## 📖 SPL Query Reference

```spl
# All events by host and sourcetype
index=* | stats count by host, sourcetype

# Failed login summary
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by host, Account_Name | sort -count

# Successful logins — post attack check
index=* sourcetype=WinEventLog:Security EventCode=4624
| where Account_Name!="SYSTEM" AND NOT match(Account_Name,"\$")
| table _time, host, Account_Name, Logon_Type | sort -_time

# Password spraying detection
index=* sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=5m
| stats dc(Account_Name) as unique_accounts, count by _time, host
| where unique_accounts >= 3 AND count >= 10

# CPU load by host
index=* sourcetype="Perfmon:CPU Load"
| timechart avg(Value) by host

# Event timeline
index=* | timechart span=1h count by host

# Top security event codes
index=* sourcetype=WinEventLog:Security | top limit=10 EventCode

# Privilege escalation check
index=* sourcetype=WinEventLog:Security EventCode=4672
| stats count by host, Account_Name | sort -count
```

---

## 🧩 Challenges & Resolutions

| Challenge | Root Cause | Resolution |
|-----------|-----------|------------|
| Forwarder not connecting | Wrong IP in `outputs.conf` | Updated to correct host IP `192.168.1.67` |
| Ping — General failure | VirtualBox set to NAT mode | Changed to Bridged Adapter |
| Ping — Request timed out | Host firewall blocking ICMP | Added inbound ICMPv4 firewall rule |
| `splunk` command not found | Running from wrong directory | `cd SplunkUniversalForwarder\bin` first |
| Login failed on CLI | Used literal text `yourpassword` | Used actual admin password |
| Triggered Alerts empty | Severity filter set to High | Changed filter to All Severities |
| Trellis error on PDF export | Panel using trellis layout | Disabled trellis in Visualization Format |
| Log scale on bar chart | Splunk defaulted to log scale | Changed Y-axis to linear in Format settings |

---

## 💡 Skills Demonstrated

- ✅ SIEM configuration and administration — Splunk Enterprise
- ✅ Log forwarding and agent deployment — Splunk Universal Forwarder
- ✅ Windows Event Log analysis — Security, System, Application
- ✅ MITRE ATT&CK framework application and detection mapping
- ✅ Threat detection rule development using SPL
- ✅ Firewall configuration — inbound and outbound rules
- ✅ Attack simulation and validation — PowerShell scripting
- ✅ Incident investigation and SOC triage workflow
- ✅ SOC dashboard design — 8 panels with live data
- ✅ Network troubleshooting — VirtualBox, Windows Firewall
- ✅ Blue team / defensive security operations
- ✅ Technical documentation and reporting

---

## 📁 Repository Structure

---

## 👤 Author

**Mopelola**
SOC Home Lab Project — May 2026
Built with Splunk Enterprise · Oracle VirtualBox · Windows Server 2022

---

> ⚠️ **Disclaimer:** This project was built entirely in an isolated home lab environment for educational and portfolio purposes. All attack simulations were conducted within a closed virtualised network. No real systems were targeted or compromised.

---

## 🏗️ Architecture
