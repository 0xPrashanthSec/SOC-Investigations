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
    SOC - Windows Remediation & Containment
    Targeted actions to contain and remediate a compromise.
    *** ALWAYS document what you do and get change approval first. ***
    *** These actions modify the system - run only when authorized. ***
    Required: Run as Administrator.

USAGE EXAMPLES:
    Kill process by PID:            .\08_Remediation.ps1 -KillPID 1234
    Kill process by name:           .\08_Remediation.ps1 -KillName "malware.exe"
    Disable service:                .\08_Remediation.ps1 -DisableService "EvilSvc"
    Remove scheduled task:          .\08_Remediation.ps1 -RemoveTask "EvilTask"
    Remove Run key entry:           .\08_Remediation.ps1 -RemoveRunKey "HKCU" -RunKeyName "Updater"
    Block IP outbound:              .\08_Remediation.ps1 -BlockIP "1.2.3.4"
    Quarantine file:                .\08_Remediation.ps1 -QuarantineFile "C:\Temp\evil.exe"
    Disable user account:           .\08_Remediation.ps1 -DisableUser "compromised_user"
    Isolate machine (network off):  .\08_Remediation.ps1 -IsolateMachine
    Remove WMI subscription:        .\08_Remediation.ps1 -RemoveWMISub "EvilFilter"
#>

param(
    [int]    $KillPID         = 0,
    [string] $KillName        = "",
    [string] $DisableService  = "",
    [string] $RemoveTask      = "",
    [string] $RemoveRunKey    = "",   # "HKCU" or "HKLM"
    [string] $RunKeyName      = "",
    [string] $BlockIP         = "",
    [string] $QuarantineFile  = "",
    [string] $DisableUser     = "",
    [string] $RemoveWMISub    = "",
    [switch] $IsolateMachine
)

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Red
Write-Host "  SOC REMEDIATION  |  $ts UTC"                          -ForegroundColor Red
Write-Host "=====================================================`n" -ForegroundColor Red

Write-Host "  !!  WARNING — DESTRUCTIVE ACTIONS AHEAD  !!" -ForegroundColor Yellow
Write-Host ""
Write-Host "  This script makes PERMANENT, potentially irreversible" -ForegroundColor Yellow
Write-Host "  changes to the system:" -ForegroundColor Yellow
Write-Host ""
Write-Host "    Kill processes      Block IPs via firewall" -ForegroundColor DarkYellow
Write-Host "    Disable services    Move / quarantine files" -ForegroundColor DarkYellow
Write-Host "    Delete reg keys     Disable user accounts" -ForegroundColor DarkYellow
Write-Host "    Remove WMI subs     FULL network isolation" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Only proceed if you are FULLY AUTHORIZED, have change" -ForegroundColor Yellow
Write-Host "  approval, and are 100%% certain of what you are doing." -ForegroundColor Yellow
Write-Host "  All actions are logged to C:\SOC_Remediation_<date>.log" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Press Ctrl+C at ANY time to abort without making changes." -ForegroundColor Cyan
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Red
Write-Host ""

$proceed = Read-Host "  I understand the risks and I am authorized to proceed (yes/no)"
if ($proceed -ne "yes") {
    Write-Host "`n  Aborted. No changes made.`n" -ForegroundColor DarkGray
    exit 0
}

Write-Host ""
Write-Host "  ACTION LOG - All changes recorded below" -ForegroundColor Yellow

function Log-Action {
    param([string]$Action, [string]$Detail)
    $entry = "[$((Get-Date -Format 'HH:mm:ss'))] $Action | $Detail"
    Write-Host $entry -ForegroundColor Green
    Add-Content -Path "C:\SOC_Remediation_$(Get-Date -Format 'yyyyMMdd').log" -Value $entry
}

# ----------------------------------------------------------
# INTERACTIVE MENU — shown when no parameters are supplied
# ----------------------------------------------------------
$noParams = ($KillPID -eq 0 -and $KillName -eq "" -and $DisableService -eq "" -and
             $RemoveTask -eq "" -and $RemoveRunKey -eq "" -and $BlockIP -eq "" -and
             $QuarantineFile -eq "" -and $DisableUser -eq "" -and $RemoveWMISub -eq "" -and
             -not $IsolateMachine)

if ($noParams) {
    Write-Host ""
    Write-Host "  Select a remediation action:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   [1]  Kill process by PID"                           -ForegroundColor White
    Write-Host "   [2]  Kill process by name"                          -ForegroundColor White
    Write-Host "   [3]  Disable and stop a service"                    -ForegroundColor White
    Write-Host "   [4]  Remove a scheduled task"                       -ForegroundColor White
    Write-Host "   [5]  Remove a registry Run key entry"               -ForegroundColor White
    Write-Host "   [6]  Block an IP address (firewall rule)"           -ForegroundColor White
    Write-Host "   [7]  Quarantine a file"                             -ForegroundColor White
    Write-Host "   [8]  Disable a local user account"                  -ForegroundColor White
    Write-Host "   [9]  Remove a WMI event subscription"               -ForegroundColor White
    Write-Host "   [10] ISOLATE MACHINE — blocks ALL network traffic"  -ForegroundColor Red
    Write-Host "   [0]  Exit / Cancel"                                 -ForegroundColor DarkGray
    Write-Host ""
    $choice = Read-Host "  Choice"
    Write-Host ""

    switch ($choice) {
        "1"  { $KillPID        = [int](Read-Host "  Enter PID to kill") }
        "2"  { $KillName       = Read-Host "  Enter process name to kill" }
        "3"  { $DisableService = Read-Host "  Enter service name to disable" }
        "4"  { $RemoveTask     = Read-Host "  Enter scheduled task name to remove" }
        "5"  {
                $RemoveRunKey  = Read-Host "  Enter hive (HKCU or HKLM)"
                $RunKeyName    = Read-Host "  Enter Run key entry name"
             }
        "6"  { $BlockIP        = Read-Host "  Enter IP address to block" }
        "7"  { $QuarantineFile = Read-Host "  Enter full file path to quarantine" }
        "8"  { $DisableUser    = Read-Host "  Enter username to disable" }
        "9"  { $RemoveWMISub   = Read-Host "  Enter WMI filter name to remove" }
        "10" { $IsolateMachine = $true }
        default {
            Write-Host "  Exiting. No action taken.`n" -ForegroundColor DarkGray
            exit 0
        }
    }
}

# ----------------------------------------------------------
# KILL PROCESS BY PID
# ----------------------------------------------------------
if ($KillPID -gt 0) {
    $proc = Get-Process -Id $KillPID -EA SilentlyContinue
    if ($proc) {
        Write-Host "`n[KILL PROCESS] PID=$KillPID Name=$($proc.Name) Path=$($proc.Path)" -ForegroundColor Yellow
        $confirm = Read-Host "  Confirm kill? (yes/no)"
        if ($confirm -eq "yes") {
            Stop-Process -Id $KillPID -Force
            Log-Action "KILL_PROCESS" "PID=$KillPID Name=$($proc.Name) Path=$($proc.Path)"
        }
    } else {
        Write-Host "  PID $KillPID not found." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# KILL PROCESS BY NAME
# ----------------------------------------------------------
if ($KillName) {
    $procs = Get-Process -Name $KillName -EA SilentlyContinue
    if ($procs) {
        $procs | Select-Object Name, Id, Path | Format-Table -AutoSize
        $confirm = Read-Host "  Kill ALL above? (yes/no)"
        if ($confirm -eq "yes") {
            $procs | Stop-Process -Force
            Log-Action "KILL_PROCESS" "Name=$KillName PIDs=$($procs.Id -join ',')"
        }
    } else {
        Write-Host "  No process named '$KillName' found." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# DISABLE AND STOP SERVICE
# ----------------------------------------------------------
if ($DisableService) {
    $svc = Get-Service -Name $DisableService -EA SilentlyContinue
    if ($svc) {
        Write-Host "`n[DISABLE SERVICE] $DisableService (Current: $($svc.Status))" -ForegroundColor Yellow
        $confirm = Read-Host "  Confirm disable and stop? (yes/no)"
        if ($confirm -eq "yes") {
            Stop-Service -Name $DisableService -Force -EA SilentlyContinue
            Set-Service -Name $DisableService -StartupType Disabled
            Log-Action "DISABLE_SERVICE" "Name=$DisableService"
        }
    } else {
        Write-Host "  Service '$DisableService' not found." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# REMOVE SCHEDULED TASK
# ----------------------------------------------------------
if ($RemoveTask) {
    $task = Get-ScheduledTask -TaskName $RemoveTask -EA SilentlyContinue
    if ($task) {
        Write-Host "`n[REMOVE TASK] $RemoveTask" -ForegroundColor Yellow
        $task | Select-Object TaskName, TaskPath | Format-Table -AutoSize
        $confirm = Read-Host "  Confirm delete? (yes/no)"
        if ($confirm -eq "yes") {
            Unregister-ScheduledTask -TaskName $RemoveTask -Confirm:$false
            Log-Action "REMOVE_SCHEDULED_TASK" "Name=$RemoveTask"
        }
    } else {
        Write-Host "  Task '$RemoveTask' not found." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# REMOVE REGISTRY RUN KEY ENTRY
# ----------------------------------------------------------
if ($RemoveRunKey -and $RunKeyName) {
    $hive = if ($RemoveRunKey -eq "HKCU") {"HKCU:"} else {"HKLM:"}
    $regPath = "$hive\Software\Microsoft\Windows\CurrentVersion\Run"
    $current = (Get-ItemProperty -Path $regPath -EA SilentlyContinue).$RunKeyName
    if ($current) {
        Write-Host "`n[REMOVE RUN KEY] $regPath\$RunKeyName = $current" -ForegroundColor Yellow
        $confirm = Read-Host "  Confirm delete? (yes/no)"
        if ($confirm -eq "yes") {
            Remove-ItemProperty -Path $regPath -Name $RunKeyName
            Log-Action "REMOVE_RUN_KEY" "Path=$regPath Name=$RunKeyName Value=$current"
        }
    } else {
        Write-Host "  Key '$RunKeyName' not found in $regPath" -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# BLOCK IP WITH WINDOWS FIREWALL
# ----------------------------------------------------------
if ($BlockIP) {
    Write-Host "`n[BLOCK IP] $BlockIP - adding outbound+inbound block rules" -ForegroundColor Yellow
    $confirm = Read-Host "  Confirm block? (yes/no)"
    if ($confirm -eq "yes") {
        $ruleName = "SOC_Block_$BlockIP"
        New-NetFirewallRule -DisplayName "$ruleName-OUT" -Direction Outbound -RemoteAddress $BlockIP -Action Block -EA SilentlyContinue
        New-NetFirewallRule -DisplayName "$ruleName-IN"  -Direction Inbound  -RemoteAddress $BlockIP -Action Block -EA SilentlyContinue
        Log-Action "BLOCK_IP" "IP=$BlockIP Rules=$ruleName-OUT,$ruleName-IN"
    }
}

# ----------------------------------------------------------
# QUARANTINE FILE
# ----------------------------------------------------------
if ($QuarantineFile -and (Test-Path $QuarantineFile)) {
    $quarDir = "C:\SOC_Quarantine"
    $hash    = (Get-FileHash -Path $QuarantineFile -Algorithm SHA256).Hash
    Write-Host "`n[QUARANTINE FILE] $QuarantineFile" -ForegroundColor Yellow
    Write-Host "  SHA256: $hash" -ForegroundColor DarkCyan
    $confirm = Read-Host "  Move to $quarDir? (yes/no)"
    if ($confirm -eq "yes") {
        New-Item -ItemType Directory -Path $quarDir -Force | Out-Null
        $dest = "$quarDir\$hash_$(Split-Path $QuarantineFile -Leaf).quarantine"
        Move-Item -Path $QuarantineFile -Destination $dest -Force
        # Remove execute permissions
        icacls $dest /deny "Everyone:(RX)" | Out-Null
        Log-Action "QUARANTINE_FILE" "Source=$QuarantineFile Dest=$dest SHA256=$hash"
    }
}

# ----------------------------------------------------------
# DISABLE USER ACCOUNT
# ----------------------------------------------------------
if ($DisableUser) {
    $user = Get-LocalUser -Name $DisableUser -EA SilentlyContinue
    if ($user) {
        Write-Host "`n[DISABLE USER] $DisableUser (Enabled: $($user.Enabled))" -ForegroundColor Yellow
        $confirm = Read-Host "  Confirm disable? (yes/no)"
        if ($confirm -eq "yes") {
            Disable-LocalUser -Name $DisableUser
            Log-Action "DISABLE_USER" "Name=$DisableUser"
        }
    } else {
        Write-Host "  User '$DisableUser' not found." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# REMOVE WMI SUBSCRIPTION
# ----------------------------------------------------------
if ($RemoveWMISub) {
    Write-Host "`n[REMOVE WMI SUBSCRIPTION] Filter: $RemoveWMISub" -ForegroundColor Yellow
    $filter = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='$RemoveWMISub'" -EA SilentlyContinue
    if ($filter) {
        $confirm = Read-Host "  Confirm remove filter, consumer, and binding? (yes/no)"
        if ($confirm -eq "yes") {
            Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
                Where-Object { $_.Filter.Name -eq $RemoveWMISub } |
                Remove-CimInstance
            Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
                Where-Object { $_.Name -eq $RemoveWMISub } |
                Remove-CimInstance -EA SilentlyContinue
            $filter | Remove-CimInstance
            Log-Action "REMOVE_WMI_SUB" "FilterName=$RemoveWMISub"
        }
    } else {
        Write-Host "  WMI filter '$RemoveWMISub' not found." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# ISOLATE MACHINE - NUCLEAR OPTION
# ----------------------------------------------------------
if ($IsolateMachine) {
    Write-Host "`n[ISOLATE MACHINE] This will block ALL inbound/outbound traffic!" -ForegroundColor Red
    Write-Host "  Make sure you have an out-of-band management channel (IPMI/iDRAC/console) before proceeding." -ForegroundColor Red
    $confirm = Read-Host "  Type ISOLATE to confirm"
    if ($confirm -eq "ISOLATE") {
        # Block all inbound
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
        # Block all outbound
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block
        Log-Action "ISOLATE_MACHINE" "All inbound+outbound blocked at Windows Firewall level"
        Write-Host "  Machine isolated. Restore with: Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -DefaultOutboundAction Allow" -ForegroundColor Yellow
    }
}

Write-Host "`n[REMEDIATION LOG] C:\SOC_Remediation_$(Get-Date -Format 'yyyyMMdd').log`n" -ForegroundColor Green
