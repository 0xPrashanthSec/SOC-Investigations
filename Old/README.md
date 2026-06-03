# Legacy SOC Investigation Commands

This folder preserves the original SOC investigation reference material that existed before the toolkit was restructured into the current `Windows/`, `Linux/`, and `Mac/` folders.

These files are kept for historical reference. **Use the scripts in the OS-specific folders for all active investigations.**

---

## What Was Here Originally

### 1. Root-Level PowerShell One-Liners (`README.md`)

The original repo was a single flat list of Windows PowerShell commands covering:

| Command | Purpose |
| ------- | ------- |
| `Get-CimInstance Win32_StartupCommand` | AutoRuns — programs configured to start at boot |
| `Get-ADUser` | Domain account search |
| `Get-NetFirewallRule` | Active firewall rules |
| `Get-WmiObject Win32_ComputerSystem` | Last login users |
| `Get-NetTCPConnection` | Active network connections |
| `Test-NetConnection` | Open port check |
| `Get-ScheduledTask` | Scheduled tasks in Ready state |
| `Get-ItemProperty HKLM:\...\Uninstall\*` | Installed programs by date |
| `Get-WinEvent` | Application and security events |
| `Get-ItemProperty HKLM:\...\Run` | Registry autorun keys |
| `Get-Service` | Running services |
| `Get-ChildItem` | Suspicious files (recent .exe/.ps1/.bat) |
| `Get-CimInstance Win32_LogonSession` | Active logon sessions |
| `Get-DnsClientCache` | Recent DNS queries |
| `Get-WinEvent -Id 4625` | Failed login attempts |
| `Get-Process` with module inspection | DLL injection detection |
| `Get-NetTCPConnection` filtered | External network connections |
| `Get-Content ConsoleHost_history.txt` | PowerShell command history |
| `Invoke-RestMethod ip-api.com` | GeoIP lookup for remote IPs |

---

### 2. NetworkInvestigationToolkit (`NetworkInvestigationToolkit/`)

A PowerShell module (`NetworkInvestigationToolkit.psm1`) with reusable functions:

| Function | Purpose |
| -------- | ------- |
| `Get-ExternalTCPConnections` | Lists established TCP connections excluding internal IPs |
| `Get-SMBConnections` | Filters SMB port 445 connections from external IPs |
| `Get-SMBGeoInfo` | Geolocates remote IPs connected via SMB |
| `Get-SMBHostnames` | Resolves hostnames for SMB connections |
| `Get-SmbSessionInfo` | Retrieves active SMB sessions |
| `Get-SmbShareInfo` | Lists all SMB shares on the system |
| `Get-ServerWorkstationServices` | Checks status of Server and Workstation services |

---

### 3. User Account Creation (`User Account Creation/`)

A reference guide for creating and removing user accounts covering:

- **Windows:** `New-LocalUser`, `Remove-LocalUser`, password reset via `Set-LocalUser` and `Set-ADAccountPassword`
- **macOS:** `dscl . -create /Users/<name>`, `dscl . -delete /Users/<name>`
- Password resets for both local and domain accounts

---

## Where the Upgraded Versions Live

Everything above has been rewritten and expanded. Go here for active use:

| Old content | Replaced by |
| ----------- | ----------- |
| Root `README.md` one-liners | `Windows/02_NetworkInvestigation.ps1`, `Windows/03_ProcessInvestigation.ps1`, `Windows/04_PersistenceInvestigation.ps1` |
| `NetworkInvestigationToolkit/` | `Windows/NetworkInvestigationToolkit/` (same module, now properly placed) |
| `User Account Creation/User_account_creation.md` | `Windows/UserAccountManagement.md`, `Linux/UserAccountManagement.md`, `Mac/UserAccountManagement.md` |

---

## Current Toolkit Structure

```text
SOC-Investigations/
├── Windows/    — PowerShell (.ps1), run as Administrator
├── Linux/      — Bash (.sh), run as root or sudo
├── Mac/        — Bash (.sh), run as root or sudo
└── Old/        — This folder. Legacy reference only.
```

Each OS folder contains scripts numbered `01` through `08`:

```text
01_InitialTriage          — System snapshot, logged-on users
02_NetworkInvestigation   — External connections, ports, DNS, ARP
03_ProcessInvestigation   — Suspicious processes, unsigned binaries
04_PersistenceInvestigation — Run keys, cron, LaunchAgents, services
05_FileInvestigation      — Temp dirs, dropped executables, SHA256 hashes
06_LogCollection          — Auth logs, event IDs, export to disk
07_UserAccountInvestigation — Accounts, admins, SSH keys, login history
08_Remediation            — Kill, block, quarantine, isolate
```

---

*These legacy files are not maintained. Do not use them for active incident response.*
