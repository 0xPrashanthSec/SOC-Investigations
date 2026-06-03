# SOC Remote Investigation Toolkit

A structured set of scripts for SOC analysts responding to incidents on remote client machines. Covers the full investigation lifecycle: **triage → network → processes → persistence → files → logs → users → remediation**, for all three major operating systems.

---

## Structure

```text
SOC-Investigations/
├── Windows/     PowerShell scripts (.ps1) — run as Administrator
├── Linux/       Bash scripts (.sh)        — run as root or sudo
└── Mac/         Bash scripts (.sh)        — run as root or sudo
```

---

## Investigation Workflow

Follow the scripts in numbered order. Each script tells you what to look for and ends with a prompt to move to the next step.

| # | Script | What it does |
| --- | ------ | ------------ |
| 01 | `InitialTriage` | System identity, uptime, logged-on users, recent logins, top processes |
| 02 | `NetworkInvestigation` | External connections, listening ports, DNS cache, ARP, SMB, firewall |
| 03 | `ProcessInvestigation` | Running processes, suspicious paths, unsigned binaries, DLL/dylib injection |
| 04 | `PersistenceInvestigation` | Registry run keys, scheduled tasks, services, cron, LaunchAgents, shell profiles |
| 05 | `FileInvestigation` | Suspicious files in temp dirs, recently dropped executables, hashes for VirusTotal |
| 06 | `LogCollection` | Security event logs, authentication logs, exports to disk for offline analysis |
| 07 | `UserAccountInvestigation` | All accounts, admin members, SSH keys, failed logins, account creation |
| 08 | `Remediation` | Kill process, block IP, quarantine file, disable service, isolate machine |

---

## Windows

**Requirements:** PowerShell 5.1+, run as **Administrator**.

```powershell
# Run from PowerShell (Admin)
cd Windows\
.\01_InitialTriage.ps1
.\02_NetworkInvestigation.ps1
.\03_ProcessInvestigation.ps1
.\04_PersistenceInvestigation.ps1
.\05_FileInvestigation.ps1                         # or: .\05_FileInvestigation.ps1 -TargetFile "C:\path\to\file.exe"
.\06_LogCollection.ps1                             # exports CSV to C:\SOC_Logs_<timestamp>\
.\07_UserAccountInvestigation.ps1
.\08_Remediation.ps1 -BlockIP 1.2.3.4             # See script header for all options
```

**Remediation options:**

```powershell
.\08_Remediation.ps1 -KillPID 1234
.\08_Remediation.ps1 -KillName "malware.exe"
.\08_Remediation.ps1 -DisableService "EvilSvc"
.\08_Remediation.ps1 -RemoveTask "EvilTask"
.\08_Remediation.ps1 -BlockIP "1.2.3.4"
.\08_Remediation.ps1 -QuarantineFile "C:\Temp\evil.exe"
.\08_Remediation.ps1 -DisableUser "compromised_user"
.\08_Remediation.ps1 -IsolateMachine              # NUCLEAR: blocks all traffic via Windows Firewall
```

**NetworkInvestigationToolkit** (reusable PowerShell module):

```powershell
Import-Module .\Windows\NetworkInvestigationToolkit\NetworkInvestigationToolkit.psm1
Get-ExternalTCPConnections
Get-SMBConnections
Get-SMBGeoInfo
```

---

## Linux

**Requirements:** Bash, run as **root** or with **sudo**.

```bash
cd Linux/
sudo ./01_InitialTriage.sh
sudo ./02_NetworkInvestigation.sh
sudo ./03_ProcessInvestigation.sh
sudo ./04_PersistenceInvestigation.sh
sudo ./05_FileInvestigation.sh                     # or: sudo ./05_FileInvestigation.sh /path/to/file
sudo ./06_LogCollection.sh                         # exports to /tmp/soc_logs_<timestamp>/
sudo ./07_UserAccountInvestigation.sh
sudo ./08_Remediation.sh                           # run with no args to see all options
```

**Remediation options:**

```bash
sudo ./08_Remediation.sh kill_pid 1234
sudo ./08_Remediation.sh kill_name malware
sudo ./08_Remediation.sh block_ip 1.2.3.4
sudo ./08_Remediation.sh disable_service evil_svc
sudo ./08_Remediation.sh remove_cron root "/tmp/evil.sh"
sudo ./08_Remediation.sh lock_user baduser
sudo ./08_Remediation.sh quarantine /tmp/evil.elf
sudo ./08_Remediation.sh isolate                   # NUCLEAR: blocks all new connections via iptables
```

---

## Mac

**Requirements:** Bash, run as **root** or with **sudo**. Full output may require SIP-disabled or MDM-enrolled device.

```bash
cd Mac/
sudo ./01_InitialTriage.sh
sudo ./02_NetworkInvestigation.sh
sudo ./03_ProcessInvestigation.sh
sudo ./04_PersistenceInvestigation.sh
sudo ./05_FileInvestigation.sh                     # or: sudo ./05_FileInvestigation.sh /path/to/file
sudo ./06_LogCollection.sh                         # exports to /tmp/soc_logs_<timestamp>/
sudo ./07_UserAccountInvestigation.sh
sudo ./08_Remediation.sh                           # run with no args to see all options
```

**Remediation options:**

```bash
sudo ./08_Remediation.sh kill_pid 1234
sudo ./08_Remediation.sh kill_name malware
sudo ./08_Remediation.sh block_ip 1.2.3.4
sudo ./08_Remediation.sh remove_launch "/Library/LaunchAgents/evil.plist"
sudo ./08_Remediation.sh lock_user baduser
sudo ./08_Remediation.sh quarantine /tmp/evil.app
sudo ./08_Remediation.sh isolate                   # NUCLEAR: blocks all new connections via pf
```

---

## Key Indicators to Watch For

| Category | Windows | Linux | Mac |
| -------- | ------- | ----- | --- |
| Suspicious process paths | `\Temp\`, `\AppData\`, `\Downloads\` | `/tmp/`, `/dev/shm/`, `/var/tmp/` | `/tmp/`, `/private/tmp/`, `Downloads/` |
| Persistence locations | `HKLM\Run`, Scheduled Tasks, Services | cron, systemd, `~/.bashrc`, LD_PRELOAD | LaunchAgents, LaunchDaemons, login hooks |
| Unsigned binaries | `Get-AuthenticodeSignature` | `file` + `strings` | `codesign -v`, `spctl --assess` |
| Deleted executables | Prefetch, USN Journal | `/proc/*/exe (deleted)` | N/A (use Spotlight logs) |
| Lateral movement | SMB (port 445), RDP (4624 Type 10) | SSH from unusual IPs | SSH, Screen Sharing |
| Log clearance | Event ID 1102 (Security log cleared) | `/var/log/auth.log` gaps | Unified log gaps |
| Persistence via SSH | N/A | `~/.ssh/authorized_keys` | `~/.ssh/authorized_keys` |

---

## Collect Evidence Before Remediating

1. Run scripts 01–07 and save all output to a timestamped folder
2. Hash all suspicious files with SHA256 before quarantine
3. Export event logs before isolating the machine
4. Document every action taken with timestamp and authorizing analyst

---

*Maintained by the SOC team. Add new scripts via pull request with a clear description.*
