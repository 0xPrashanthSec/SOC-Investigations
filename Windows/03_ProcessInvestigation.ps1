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
    SOC - Windows Process Investigation
    Enumerates all running processes and flags anomalies.
    What to look for: processes in Temp/AppData/Downloads, unsigned binaries,
    processes masquerading as system processes, DLL injection, hollowed processes.
    Required: Run as Administrator.
#>

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Yellow
Write-Host "  SOC PROCESS INVESTIGATION  |  $ts UTC"               -ForegroundColor Yellow
Write-Host "=====================================================`n" -ForegroundColor Yellow

# ----------------------------------------------------------
Write-Host "[1] ALL RUNNING PROCESSES WITH PATHS" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-Process | Sort-Object Name |
    Select-Object Name, Id, SessionId,
        @{N="RAM(MB)"; E={[math]::Round($_.WorkingSet/1MB,1)}},
        @{N="Started"; E={$_.StartTime}},
        Path |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[2] PROCESSES RUNNING FROM SUSPICIOUS LOCATIONS" -ForegroundColor Cyan
# ----------------------------------------------------------
# Malware commonly executes from user-writable paths
$suspiciousPaths = @("\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\ProgramData\\",
                     "\\Public\\", "\\Desktop\\", "^C:\\[^\\]+\.exe$")
$allProcs = Get-Process | Where-Object { $_.Path }
$suspicious = $allProcs | Where-Object {
    $path = $_.Path
    ($path -match "Temp" -or $path -match "AppData" -or $path -match "Downloads" -or
     $path -match "ProgramData" -or $path -match "\\Public\\" -or
     ($path -match "^C:\\" -and $path -notmatch "\\Windows\\" -and $path -notmatch "\\Program Files"))
}
if ($suspicious) {
    $suspicious | Select-Object Name, Id, Path,
        @{N="Started";E={$_.StartTime}} | Format-Table -AutoSize
} else {
    Write-Host "  No processes found in suspicious locations." -ForegroundColor Green
}

# ----------------------------------------------------------
Write-Host "[3] PROCESSES WITH EXTERNAL NETWORK CONNECTIONS" -ForegroundColor Cyan
# ----------------------------------------------------------
$extConns = Get-NetTCPConnection -State Established |
    Where-Object {
        $_.RemoteAddress -notmatch "^127\." -and $_.RemoteAddress -notmatch "^192\.168\." -and
        $_.RemoteAddress -notmatch "^10\." -and $_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "0.0.0.0"
    }
$(foreach ($conn in $extConns) {
    $proc = Get-Process -Id $conn.OwningProcess -EA SilentlyContinue
    [PSCustomObject]@{
        ProcessName = $proc.Name
        PID         = $conn.OwningProcess
        Path        = $proc.Path
        RemoteIP    = $conn.RemoteAddress
        RemotePort  = $conn.RemotePort
    }
}) | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[4] PROCESS SIGNATURE VERIFICATION" -ForegroundColor Cyan
# ----------------------------------------------------------
# Unsigned processes or processes with revoked/invalid signatures are high priority
Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.Path -EA SilentlyContinue
    if ($sig -and $sig.Status -ne 'Valid') {
        [PSCustomObject]@{
            Name   = $_.Name
            PID    = $_.Id
            Status = $sig.Status
            Path   = $_.Path
        }
    }
} | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[5] DLL INJECTION DETECTION - Non-standard DLLs in processes" -ForegroundColor Cyan
# ----------------------------------------------------------
# DLLs loaded from non-Windows/non-ProgramFiles paths inside trusted processes
Get-Process | Where-Object { $_.Name -in @("svchost","lsass","explorer","winlogon","csrss") } |
    ForEach-Object {
        $proc = $_
        try {
            $proc.Modules | Where-Object {
                $_.FileName -notlike "C:\Windows\*" -and
                $_.FileName -notlike "C:\Program Files*"
            } | ForEach-Object {
                [PSCustomObject]@{
                    HostProcess = $proc.Name
                    HostPID     = $proc.Id
                    DLL         = $_.FileName
                }
            }
        } catch {}
    } | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[6] PROCESSES STARTED IN LAST 24 HOURS" -ForegroundColor Cyan
# ----------------------------------------------------------
$cutoff = (Get-Date).AddHours(-24)
Get-Process | Where-Object { $_.StartTime -and $_.StartTime -gt $cutoff } |
    Sort-Object StartTime -Descending |
    Select-Object Name, Id, StartTime, Path | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[7] SHA256 HASHES OF PROCESSES FROM SUSPICIOUS PATHS" -ForegroundColor Cyan
# ----------------------------------------------------------
# Hash for VirusTotal lookup
$suspicious | ForEach-Object {
    if ($_.Path -and (Test-Path $_.Path)) {
        [PSCustomObject]@{
            Name   = $_.Name
            PID    = $_.Id
            Hash   = (Get-FileHash -Path $_.Path -Algorithm SHA256).Hash
            Path   = $_.Path
        }
    }
} | Format-Table -AutoSize

Write-Host "`n[PROCESS DONE] => Run 04_PersistenceInvestigation.ps1 next`n" -ForegroundColor Green
