<#
.SYNOPSIS
    SOC - Windows Initial Triage
    Run FIRST on any suspected compromised Windows machine.
    Captures identity, timing, active users, and system state at moment of investigation.
    Required: Run PowerShell as Administrator.
#>

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Yellow
Write-Host "  SOC WINDOWS INITIAL TRIAGE  |  $ts UTC"             -ForegroundColor Yellow
Write-Host "=====================================================`n" -ForegroundColor Yellow

# ----------------------------------------------------------
Write-Host "[1] SYSTEM IDENTITY" -ForegroundColor Cyan
# ----------------------------------------------------------
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
[PSCustomObject]@{
    Hostname     = $env:COMPUTERNAME
    Domain       = $cs.Domain
    CurrentUser  = $cs.UserName
    OS           = $os.Caption
    Build        = $os.BuildNumber
    Architecture = $os.OSArchitecture
    LastBoot     = $os.LastBootUpTime
    Uptime       = "$([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)) hours"
} | Format-List

# ----------------------------------------------------------
Write-Host "[2] NETWORK INTERFACES" -ForegroundColor Cyan
# ----------------------------------------------------------
# Multiple IPs on one interface or unexpected adapters can indicate tunneling
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressState |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[3] WHO IS LOGGED ON RIGHT NOW" -ForegroundColor Cyan
# ----------------------------------------------------------
# Multiple active sessions may indicate unauthorized remote access
try {
    $sessions = query user 2>&1
    $sessions
} catch {
    Get-CimInstance Win32_LoggedOnUser |
        Select-Object @{N="User";E={$_.Antecedent.ToString().Split('"')[1]}},
                      @{N="Domain";E={$_.Antecedent.ToString().Split('"')[3]}} |
        Sort-Object User -Unique | Format-Table -AutoSize
}

# ----------------------------------------------------------
Write-Host "[4] LAST 10 INTERACTIVE LOGINS" -ForegroundColor Cyan
# ----------------------------------------------------------
# LogonType 2=Interactive, 10=RemoteInteractive (RDP)
try {
    Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 100 -EA Stop |
        Where-Object { $_.Properties[8].Value -in @(2,10) } |
        Select-Object -First 10 TimeCreated,
            @{N="User";    E={"$($_.Properties[6].Value)\$($_.Properties[5].Value)"}},
            @{N="Type";    E={if ($_.Properties[8].Value -eq 2) {"Local"} else {"RDP"}}},
            @{N="SourceIP";E={$_.Properties[18].Value}} |
        Format-Table -AutoSize
} catch {
    Write-Host "  Cannot read Security log. Ensure you are running as Administrator." -ForegroundColor Red
}

# ----------------------------------------------------------
Write-Host "[5] TOP 15 PROCESSES BY CPU" -ForegroundColor Cyan
# ----------------------------------------------------------
# Unusual process names, processes in Temp/AppData, or high CPU with no description are red flags
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 |
    Select-Object Name, Id,
        @{N="CPU(s)";    E={[math]::Round($_.CPU,1)}},
        @{N="RAM(MB)";   E={[math]::Round($_.WorkingSet/1MB,1)}},
        @{N="Started";   E={$_.StartTime}},
        Path |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[6] RECENTLY INSTALLED SOFTWARE (last 7 days)" -ForegroundColor Cyan
# ----------------------------------------------------------
$cutoff = (Get-Date).AddDays(-7).ToString("yyyyMMdd")
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
    Where-Object { $_.InstallDate -ge $cutoff -and $_.DisplayName } |
    Select-Object DisplayName, InstallDate, Publisher |
    Sort-Object InstallDate -Descending | Format-Table -AutoSize

Write-Host "`n[TRIAGE DONE] => Run 02_NetworkInvestigation.ps1 next`n" -ForegroundColor Green
