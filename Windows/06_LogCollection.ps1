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
    SOC - Windows Log Collection & Analysis
    Pulls critical event logs and exports to CSV for offline analysis.
    Key Event IDs:
      4624 - Successful logon   | 4625 - Failed logon
      4648 - Explicit credential use (pass-the-hash indicator)
      4720 - Account created    | 4726 - Account deleted
      4732 - Added to admin group
      4688 - Process created (if Audit Process Creation is enabled)
      4103/4104 - PowerShell script block logging
      7045 - New service installed
      1102 - Security log cleared (!!!immediate red flag!!!)
    Required: Run as Administrator. Logs exported to $OutputDir.
#>

param(
    [string]$OutputDir = "C:\SOC_Logs_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Yellow
Write-Host "  SOC LOG COLLECTION  |  $ts UTC"                       -ForegroundColor Yellow
Write-Host "  Output: $OutputDir"                                    -ForegroundColor Yellow
Write-Host "=====================================================`n" -ForegroundColor Yellow

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Helper: collect events and display + export
function Get-AndExport {
    param($FilterHash, $Label, $File, $MaxEvents = 100, $Props)
    Write-Host "`n[$Label]" -ForegroundColor Cyan
    try {
        $events = Get-WinEvent -FilterHashtable $FilterHash -MaxEvents $MaxEvents -EA Stop
        $results = $events | Select-Object -Property $Props
        $results | Format-Table -AutoSize
        $results | Export-Csv -Path "$OutputDir\$File" -NoTypeInformation
        Write-Host "  Exported $($results.Count) events to $File" -ForegroundColor DarkGreen
    } catch {
        Write-Host "  No events found or log inaccessible." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------
# SECURITY LOG
# ----------------------------------------------------------
Get-AndExport @{LogName="Security"; Id=4625} `
    "FAILED LOGINS (4625) - last 100" "failed_logins.csv" 100 `
    @("TimeCreated",
      @{N="Account";  E={$_.Properties[5].Value}},
      @{N="Domain";   E={$_.Properties[6].Value}},
      @{N="LogonType";E={$_.Properties[10].Value}},
      @{N="SourceIP"; E={$_.Properties[19].Value}},
      @{N="Workstation";E={$_.Properties[13].Value}})

Get-AndExport @{LogName="Security"; Id=4624} `
    "SUCCESSFUL LOGINS (4624) - last 100" "successful_logins.csv" 100 `
    @("TimeCreated",
      @{N="Account";  E={$_.Properties[5].Value}},
      @{N="Domain";   E={$_.Properties[6].Value}},
      @{N="LogonType";E={$_.Properties[8].Value}},
      @{N="SourceIP"; E={$_.Properties[18].Value}})

Get-AndExport @{LogName="Security"; Id=4648} `
    "EXPLICIT CREDENTIAL USE (4648) - Pass-the-Hash indicator" "explicit_credentials.csv" 50 `
    @("TimeCreated",
      @{N="Account";     E={$_.Properties[1].Value}},
      @{N="TargetServer";E={$_.Properties[8].Value}},
      @{N="TargetUser";  E={$_.Properties[5].Value}},
      @{N="Process";     E={$_.Properties[11].Value}})

Get-AndExport @{LogName="Security"; Id=4720} `
    "ACCOUNT CREATED (4720)" "account_created.csv" 50 `
    @("TimeCreated",
      @{N="NewAccount";E={$_.Properties[0].Value}},
      @{N="CreatedBy"; E={$_.Properties[4].Value}})

Get-AndExport @{LogName="Security"; Id=4726} `
    "ACCOUNT DELETED (4726)" "account_deleted.csv" 50 `
    @("TimeCreated",
      @{N="DeletedAccount";E={$_.Properties[0].Value}},
      @{N="DeletedBy";     E={$_.Properties[4].Value}})

Get-AndExport @{LogName="Security"; Id=4732} `
    "ADDED TO PRIVILEGED GROUP (4732)" "group_changes.csv" 50 `
    @("TimeCreated",
      @{N="Group";       E={$_.Properties[2].Value}},
      @{N="NewMember";   E={$_.Properties[0].Value}},
      @{N="AddedBy";     E={$_.Properties[6].Value}})

Get-AndExport @{LogName="Security"; Id=1102} `
    "SECURITY LOG CLEARED (1102) - !!!RED FLAG!!!" "log_cleared.csv" 20 `
    @("TimeCreated", @{N="ClearedBy";E={$_.Properties[1].Value}}, "Message")

Get-AndExport @{LogName="Security"; Id=4688} `
    "PROCESS CREATION (4688) - last 200" "process_creation.csv" 200 `
    @("TimeCreated",
      @{N="Process";  E={$_.Properties[5].Value}},
      @{N="CommandLine";E={$_.Properties[8].Value}},
      @{N="Parent";   E={$_.Properties[13].Value}},
      @{N="User";     E={$_.Properties[1].Value}})

# ----------------------------------------------------------
# SYSTEM LOG
# ----------------------------------------------------------
Get-AndExport @{LogName="System"; Id=7045} `
    "NEW SERVICE INSTALLED (7045)" "new_services.csv" 50 `
    @("TimeCreated",
      @{N="ServiceName";E={$_.Properties[0].Value}},
      @{N="Path";       E={$_.Properties[1].Value}},
      @{N="StartType";  E={$_.Properties[2].Value}},
      @{N="Account";    E={$_.Properties[4].Value}})

Get-AndExport @{LogName="System"; Id=7036} `
    "SERVICE STATE CHANGES (7036) - last 50" "service_changes.csv" 50 `
    @("TimeCreated", @{N="Service";E={$_.Properties[0].Value}}, @{N="State";E={$_.Properties[1].Value}})

# ----------------------------------------------------------
# POWERSHELL LOGS
# ----------------------------------------------------------
Get-AndExport @{LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104} `
    "POWERSHELL SCRIPT BLOCK LOGGING (4104)" "powershell_scriptblock.csv" 100 `
    @("TimeCreated", "Message")

Get-AndExport @{LogName="Microsoft-Windows-PowerShell/Operational"; Id=4103} `
    "POWERSHELL MODULE LOGGING (4103)" "powershell_module.csv" 100 `
    @("TimeCreated", "Message")

# ----------------------------------------------------------
Write-Host "`n[LOG SIZES]" -ForegroundColor Cyan
# ----------------------------------------------------------
@("Security","System","Application","Microsoft-Windows-PowerShell/Operational") | ForEach-Object {
    try {
        $log = Get-WinEvent -ListLog $_ -EA Stop
        [PSCustomObject]@{
            Log        = $_
            Size_MB    = [math]::Round($log.FileSize/1MB, 1)
            MaxSize_MB = [math]::Round($log.MaximumSizeInBytes/1MB, 1)
            Enabled    = $log.IsEnabled
            Retention  = $log.LogMode
        }
    } catch {}
} | Format-Table -AutoSize

Write-Host "`n[LOGS DONE] All CSV files saved to: $OutputDir" -ForegroundColor Green
Write-Host "[LOGS DONE] => Run 07_UserAccountInvestigation.ps1 next`n" -ForegroundColor Green
