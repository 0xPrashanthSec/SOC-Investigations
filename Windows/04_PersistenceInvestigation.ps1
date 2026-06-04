<#
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
.SYNOPSIS
    SOC - Windows Persistence Investigation
    Enumerates all known persistence mechanisms.
    What to look for: entries pointing to Temp/AppData, encoded PowerShell,
    recently added tasks/services, WMI subscriptions, unsigned binaries.
    Required: Run as Administrator.
#>

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Yellow
Write-Host "  SOC PERSISTENCE INVESTIGATION  |  $ts UTC"            -ForegroundColor Yellow
Write-Host "=====================================================`n" -ForegroundColor Yellow

# ----------------------------------------------------------
Write-Host "[1] REGISTRY RUN KEYS (System-wide)" -ForegroundColor Cyan
# ----------------------------------------------------------
# Most common malware persistence location
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$(foreach ($key in $runKeys) {
    Write-Host "  $key" -ForegroundColor DarkCyan
    try {
        $props = Get-ItemProperty -Path $key -EA Stop
        $props.PSObject.Properties |
            Where-Object { $_.Name -notlike "PS*" } |
            ForEach-Object { [PSCustomObject]@{Key=$key; Name=$_.Name; Value=$_.Value} }
    } catch { Write-Host "  Key not found or no access." }
}) | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[2] SCHEDULED TASKS (non-Microsoft)" -ForegroundColor Cyan
# ----------------------------------------------------------
# Look for tasks with encoded commands, tasks in root folder, recently created tasks
Get-ScheduledTask |
    Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
    ForEach-Object {
        $action = $_.Actions | Select-Object -First 1
        [PSCustomObject]@{
            Name     = $_.TaskName
            Path     = $_.TaskPath
            State    = $_.State
            Author   = $_.Principal.UserId
            Command  = $action.Execute
            Args     = $action.Arguments
        }
    } | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[3] SERVICES - Non-Microsoft, Auto-Start" -ForegroundColor Cyan
# ----------------------------------------------------------
# Attacker-installed services often have random names or no description
Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' } |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature -FilePath $_.PathName.Trim('"').Split(' ')[0] -EA SilentlyContinue
        [PSCustomObject]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            State       = $_.State
            StartMode   = $_.StartMode
            Path        = $_.PathName
            Signed      = $sig.Status
            RunAs       = $_.StartName
        }
    } |
    Where-Object { $_.Signed -ne 'Valid' -or $_.Path -match "Temp|AppData|ProgramData" } |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[4] STARTUP FOLDERS" -ForegroundColor Cyan
# ----------------------------------------------------------
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($path in $startupPaths) {
    Write-Host "  $path" -ForegroundColor DarkCyan
    Get-ChildItem -Path $path -EA SilentlyContinue |
        Select-Object Name, FullName, CreationTime, LastWriteTime | Format-Table -AutoSize
}

# ----------------------------------------------------------
Write-Host "[5] WMI PERMANENT EVENT SUBSCRIPTIONS" -ForegroundColor Cyan
# ----------------------------------------------------------
# Advanced fileless persistence - filter, consumer, and binding
Write-Host "  Event Filters:" -ForegroundColor DarkYellow
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
    Select-Object Name, Query | Format-Table -AutoSize
Write-Host "  Event Consumers:" -ForegroundColor DarkYellow
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
    Select-Object Name, ExecutablePath, CommandLineTemplate, ScriptText | Format-Table -AutoSize
Write-Host "  Filter-To-Consumer Bindings:" -ForegroundColor DarkYellow
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Select-Object Filter, Consumer | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[6] AUTORUN ENTRIES (via CIM)" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-CimInstance -ClassName Win32_StartupCommand |
    Select-Object Name, Command, Location, User | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[7] BOOT EXECUTE AND LSA PACKAGES" -ForegroundColor Cyan
# ----------------------------------------------------------
# Persistence that runs before Windows fully loads
Write-Host "  BootExecute:" -ForegroundColor DarkCyan
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -EA SilentlyContinue).BootExecute

Write-Host "  LSA Authentication Packages:" -ForegroundColor DarkCyan
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).AuthenticationPackages

Write-Host "  LSA Security Packages:" -ForegroundColor DarkCyan
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue)."Security Packages"

# ----------------------------------------------------------
Write-Host "[8] RECENTLY MODIFIED SERVICE BINARIES (last 7 days)" -ForegroundColor Cyan
# ----------------------------------------------------------
$cutoff = (Get-Date).AddDays(-7)
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName } |
    ForEach-Object {
        $exe = $_.PathName.Trim('"').Split(' ')[0]
        if (Test-Path $exe -EA SilentlyContinue) {
            $file = Get-Item $exe -EA SilentlyContinue
            if ($file.LastWriteTime -gt $cutoff) {
                [PSCustomObject]@{Name=$_.Name; Path=$exe; Modified=$file.LastWriteTime}
            }
        }
    } | Format-Table -AutoSize

Write-Host "`n[PERSISTENCE DONE] => Run 05_FileInvestigation.ps1 next`n" -ForegroundColor Green
