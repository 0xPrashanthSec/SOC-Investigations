# SOC Remote Investigation Toolkit

A practical, script-based toolkit for SOC analysts conducting remote incident response on client machines running **Windows**, **Linux**, or **macOS**. Covers the complete investigation lifecycle from first login to final cleanup.

> Built for analysts who remote into a client machine and need to know exactly what commands to run, in what order, and what to look for at each step.

---

## Repository Structure

```text
SOC-Investigations/
│
├── Windows/                        PowerShell (.ps1) — run as Administrator
│   ├── 01_InitialTriage.ps1
│   ├── 02_NetworkInvestigation.ps1
│   ├── 03_ProcessInvestigation.ps1
│   ├── 04_PersistenceInvestigation.ps1
│   ├── 05_FileInvestigation.ps1
│   ├── 06_LogCollection.ps1
│   ├── 07_UserAccountInvestigation.ps1
│   ├── 08_Remediation.ps1
│   ├── UserAccountManagement.md
│   └── NetworkInvestigationToolkit/
│       ├── NetworkInvestigationToolkit.psm1
│       └── NetworkInvestigationToolkit.md
│
├── Linux/                          Bash (.sh) — run as root or sudo
│   ├── 01_InitialTriage.sh
│   ├── 02_NetworkInvestigation.sh
│   ├── 03_ProcessInvestigation.sh
│   ├── 04_PersistenceInvestigation.sh
│   ├── 05_FileInvestigation.sh
│   ├── 06_LogCollection.sh
│   ├── 07_UserAccountInvestigation.sh
│   ├── 08_Remediation.sh
│   └── UserAccountManagement.md
│
├── Mac/                            Bash (.sh) — run as root or sudo
│   ├── 01_InitialTriage.sh
│   ├── 02_NetworkInvestigation.sh
│   ├── 03_ProcessInvestigation.sh
│   ├── 04_PersistenceInvestigation.sh
│   ├── 05_FileInvestigation.sh
│   ├── 06_LogCollection.sh
│   ├── 07_UserAccountInvestigation.sh
│   ├── 08_Remediation.sh
│   └── UserAccountManagement.md
│
├── .github/
│   ├── workflows/
│   │   ├── powershell.yml          PSScriptAnalyzer — lints all .ps1 files on push/PR
│   │   ├── label.yml               Auto-labels PRs by changed folder (Windows/Linux/Mac)
│   │   └── greetings.yml           Welcomes first-time contributors
│   └── labeler.yml                 Label routing config for label.yml
│
├── Old/                            Legacy reference material
│   └── README.md
│
└── NetworkInvestigationToolkit/    Original standalone PowerShell module (legacy)
    ├── NetworkInvestigationToolkit.psm1
    └── NetworkInvestigationToolkit.md
```

---

## Investigation Workflow

Run scripts in numbered order on the target machine. Each script outputs what to look for and tells you which script to run next.

| Step | Script | What It Does |
| ---- | ------ | ------------ |
| 01 | `InitialTriage` | System identity, uptime, logged-on users, recent logins, top processes |
| 02 | `NetworkInvestigation` | External connections, listening ports, DNS cache, ARP table, SMB, firewall rules |
| 03 | `ProcessInvestigation` | All processes, suspicious paths, unsigned binaries, DLL/dylib injection detection |
| 04 | `PersistenceInvestigation` | Run keys, scheduled tasks, services, cron jobs, LaunchAgents, shell profile modifications |
| 05 | `FileInvestigation` | Recent executables in temp dirs, ADS streams, mismatched extensions, SHA256 hashes |
| 06 | `LogCollection` | Auth logs, security event IDs, PowerShell logs — all exported to timestamped folder |
| 07 | `UserAccountInvestigation` | All accounts, admin group members, SSH keys, failed login counts |
| 08 | `Remediation` | Kill process, block IP, quarantine file, disable service, isolate machine — interactive menu when run with no args |

---

## Windows

**Requirements:** PowerShell 5.1+, run as **Administrator**.

```powershell
cd Windows\
.\01_InitialTriage.ps1
.\02_NetworkInvestigation.ps1
.\03_ProcessInvestigation.ps1
.\04_PersistenceInvestigation.ps1
.\05_FileInvestigation.ps1
.\06_LogCollection.ps1                   # Exports CSV files to C:\SOC_Logs_<timestamp>\
.\07_UserAccountInvestigation.ps1
.\08_Remediation.ps1                     # No args: shows warning banner + interactive menu
```

**Investigate a specific file:**

```powershell
.\05_FileInvestigation.ps1 -TargetFile "C:\Users\user\Downloads\suspicious.exe"
```

**Remediation options:**

> **Warning:** `08_Remediation.ps1` makes permanent, potentially irreversible changes. It always displays a warning banner and requires explicit confirmation before executing. Running with no arguments launches an interactive numbered menu so you can select and configure the action interactively.

```powershell
.\08_Remediation.ps1                                          # Interactive menu
.\08_Remediation.ps1 -KillPID 1234
.\08_Remediation.ps1 -KillName "malware.exe"
.\08_Remediation.ps1 -DisableService "EvilService"
.\08_Remediation.ps1 -RemoveTask "EvilTask"
.\08_Remediation.ps1 -RemoveRunKey "HKCU" -RunKeyName "Updater"
.\08_Remediation.ps1 -BlockIP "1.2.3.4"
.\08_Remediation.ps1 -QuarantineFile "C:\Temp\evil.exe"
.\08_Remediation.ps1 -DisableUser "compromised_user"
.\08_Remediation.ps1 -RemoveWMISub "EvilFilter"
.\08_Remediation.ps1 -IsolateMachine                          # Blocks ALL network traffic
```

**NetworkInvestigationToolkit — reusable PowerShell module:**

```powershell
Import-Module .\NetworkInvestigationToolkit\NetworkInvestigationToolkit.psm1

Get-ExternalTCPConnections    # All non-RFC1918 TCP connections with process info
Get-SMBConnections            # External SMB (port 445) connections
Get-SMBGeoInfo                # Geolocate IPs connected via SMB
Get-SMBHostnames              # Resolve hostnames for SMB connections
Get-SmbSessionInfo            # Active SMB sessions
Get-SmbShareInfo              # All SMB shares on the system
Get-ServerWorkstationServices # Status of Server and Workstation services
```

**User account management reference:** `Windows/UserAccountManagement.md`

---

## Linux

**Requirements:** Bash, run as **root** or with **sudo**.

```bash
cd Linux/
sudo ./01_InitialTriage.sh
sudo ./02_NetworkInvestigation.sh
sudo ./03_ProcessInvestigation.sh
sudo ./04_PersistenceInvestigation.sh
sudo ./05_FileInvestigation.sh
sudo ./06_LogCollection.sh               # Exports logs to /tmp/soc_logs_<timestamp>/
sudo ./07_UserAccountInvestigation.sh
sudo ./08_Remediation.sh                 # Run with no args to see all options
```

**Investigate a specific file:**

```bash
sudo ./05_FileInvestigation.sh /path/to/suspicious.elf
```

**Remediation options:**

```bash
sudo ./08_Remediation.sh kill_pid 1234
sudo ./08_Remediation.sh kill_name malware
sudo ./08_Remediation.sh block_ip 1.2.3.4
sudo ./08_Remediation.sh disable_service evil_service
sudo ./08_Remediation.sh remove_cron root "/tmp/evil.sh"
sudo ./08_Remediation.sh lock_user baduser
sudo ./08_Remediation.sh delete_user baduser
sudo ./08_Remediation.sh remove_ssh_key username "key_comment"
sudo ./08_Remediation.sh quarantine /tmp/evil.elf
sudo ./08_Remediation.sh isolate
```

**User account management reference:** `Linux/UserAccountManagement.md`

---

## Mac

**Requirements:** Bash, run as **root** or with **sudo**. Full output on some checks may require SIP to be disabled or the device to be MDM-enrolled.

```bash
cd Mac/
sudo ./01_InitialTriage.sh
sudo ./02_NetworkInvestigation.sh
sudo ./03_ProcessInvestigation.sh
sudo ./04_PersistenceInvestigation.sh
sudo ./05_FileInvestigation.sh
sudo ./06_LogCollection.sh               # Exports logs to /tmp/soc_logs_<timestamp>/
sudo ./07_UserAccountInvestigation.sh
sudo ./08_Remediation.sh                 # Run with no args to see all options
```

**Investigate a specific file:**

```bash
sudo ./05_FileInvestigation.sh /path/to/suspicious.app
```

**Remediation options:**

```bash
sudo ./08_Remediation.sh kill_pid 1234
sudo ./08_Remediation.sh kill_name malware
sudo ./08_Remediation.sh block_ip 1.2.3.4
sudo ./08_Remediation.sh remove_launch "/Library/LaunchAgents/evil.plist"
sudo ./08_Remediation.sh disable_service com.evil.agent
sudo ./08_Remediation.sh lock_user baduser
sudo ./08_Remediation.sh delete_user baduser
sudo ./08_Remediation.sh remove_ssh_key username "key_comment"
sudo ./08_Remediation.sh quarantine /tmp/evil.app
sudo ./08_Remediation.sh disable_network
sudo ./08_Remediation.sh isolate
```

**User account management reference:** `Mac/UserAccountManagement.md`

---

## Key Red Flags by OS

| Category | Windows | Linux | Mac |
| -------- | ------- | ----- | --- |
| Suspicious process path | `\Temp\`, `\AppData\`, `\Downloads\` | `/tmp/`, `/dev/shm/`, `/var/tmp/` | `/tmp/`, `/private/tmp/`, `Downloads/` |
| Persistence | `HKLM\Run`, Scheduled Tasks, Services, WMI | cron, systemd, `~/.bashrc`, LD_PRELOAD | LaunchAgents, LaunchDaemons, login hooks |
| Unsigned binary | `Get-AuthenticodeSignature` | `file` + `strings` | `codesign -v`, `spctl --assess` |
| Deleted binary still running | Prefetch / USN Journal | `/proc/*/exe (deleted)` | Spotlight / unified log |
| Lateral movement | SMB port 445, RDP (Event 4624 Type 10) | SSH from unexpected IPs | SSH, Screen Sharing |
| Log tampered | Event ID 1102 (Security log cleared) | Gaps in `/var/log/auth.log` | Gaps in unified log |
| Backdoor SSH key | N/A | `~/.ssh/authorized_keys` | `~/.ssh/authorized_keys` |

---

## CI / Code Quality

All pull requests are automatically checked by GitHub Actions:

| Workflow | What it does |
| -------- | ------------ |
| **PSScriptAnalyzer** | Lints every `.ps1` file for syntax errors and security rules on every push and PR to `main` |
| **Labeler** | Automatically applies `Windows` / `Linux` / `Mac` / `documentation` / `CI/CD` labels to PRs based on which folders were changed |
| **Greetings** | Welcomes first-time contributors when they open their first issue or PR |

PRs should pass PSScriptAnalyzer before merging.

---

## Evidence Collection Rules

1. **Run 01–07 first** — collect and save all output before taking any action
2. **Hash before quarantine** — SHA256 every suspicious file and note it in your case file
3. **Export logs before isolation** — once the machine is isolated, remote log export is gone
4. **Log every remediation action** — script 08 writes to a timestamped log file automatically
5. **Get change approval** — remediation scripts confirm before executing anything destructive

---

## Legacy Files

The `Old/`, `NetworkInvestigationToolkit/`, and `User Account Creation/` folders at the root contain the original reference material that predates this structured toolkit. They are kept for historical reference only. See `Old/README.md` for a full index of what was there and where each piece was replaced.

---

*Maintained by [@0xPrashanthSec](https://github.com/0xPrashanthSec). Submit new scripts or improvements via pull request.*
