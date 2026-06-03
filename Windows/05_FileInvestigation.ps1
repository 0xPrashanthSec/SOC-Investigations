<#
.SYNOPSIS
    SOC - Windows File Investigation
    Hunts for malicious or suspicious files on the file system.
    What to look for: executables in user-writable paths, files with spoofed extensions,
    Alternate Data Streams, recently dropped binaries.
    Required: Run as Administrator. Modify $TargetFile to hash a specific file.
#>

param(
    [string]$TargetFile = ""  # Optional: full path to a specific file to investigate
)

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Yellow
Write-Host "  SOC FILE INVESTIGATION  |  $ts UTC"                   -ForegroundColor Yellow
Write-Host "=====================================================`n" -ForegroundColor Yellow

# ----------------------------------------------------------
Write-Host "[1] RECENTLY CREATED EXECUTABLES (last 7 days, user-writable paths)" -ForegroundColor Cyan
# ----------------------------------------------------------
$suspPaths = @("C:\Users", "C:\ProgramData", "C:\Windows\Temp", "$env:TEMP")
$cutoff7   = (Get-Date).AddDays(-7)
Get-ChildItem -Path $suspPaths -Recurse -EA SilentlyContinue -Include *.exe,*.dll,*.bat,*.ps1,*.vbs,*.js,*.hta,*.scr,*.cmd |
    Where-Object { $_.CreationTime -gt $cutoff7 } |
    Select-Object FullName, CreationTime, LastWriteTime,
        @{N="Size(KB)"; E={[math]::Round($_.Length/1KB,1)}} |
    Sort-Object CreationTime -Descending | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[2] FILES IN TEMP DIRECTORIES RIGHT NOW" -ForegroundColor Cyan
# ----------------------------------------------------------
# Any executable sitting in Temp is suspicious by default
Get-ChildItem -Path "C:\Windows\Temp", $env:TEMP, "C:\ProgramData\Temp" -EA SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime,
        @{N="Size(KB)"; E={[math]::Round($_.Length/1KB,1)}} |
    Sort-Object LastWriteTime -Descending | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[3] ALTERNATE DATA STREAMS (ADS)" -ForegroundColor Cyan
# ----------------------------------------------------------
# Malware can hide payloads in NTFS ADS. Zone.Identifier is normal (download marker). Others are not.
Get-ChildItem -Path "C:\Users" -Recurse -EA SilentlyContinue |
    ForEach-Object {
        $streams = Get-Item -Path $_.FullName -Stream * -EA SilentlyContinue |
            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        if ($streams) {
            foreach ($s in $streams) {
                [PSCustomObject]@{File=$_.FullName; Stream=$s.Stream; Size=$s.Length}
            }
        }
    } | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[4] FILES WITH MISMATCHED EXTENSIONS" -ForegroundColor Cyan
# ----------------------------------------------------------
# e.g., a PE binary renamed to .pdf or .docx
$checkPaths = @("C:\Users\$env:USERNAME\Downloads", "C:\Users\$env:USERNAME\Desktop",
                "$env:TEMP", "C:\ProgramData")
foreach ($path in $checkPaths) {
    Get-ChildItem -Path $path -Recurse -EA SilentlyContinue -File |
        Where-Object { $_.Extension -in @('.pdf','.docx','.xlsx','.jpg','.png','.txt') } |
        ForEach-Object {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)[0..3]
            $hex   = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ''
            # PE header = 4D5A (MZ), ZIP = 504B0304, PDF = 25504446
            if ($hex -like "4D5A*") {
                [PSCustomObject]@{File=$_.FullName; Extension=$_.Extension; MagicBytes=$hex; Verdict="PE binary with wrong extension!"}
            }
        }
} | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[5] POWERSHELL HISTORY (all users)" -ForegroundColor Cyan
# ----------------------------------------------------------
# Look for: encoded commands (-EncodedCommand), IEX, DownloadString, bypass flags
$users = Get-ChildItem "C:\Users" -Directory -EA SilentlyContinue
foreach ($user in $users) {
    $histFile = "$($user.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histFile) {
        Write-Host "  User: $($user.Name)" -ForegroundColor DarkCyan
        Get-Content $histFile -EA SilentlyContinue | Select-Object -Last 30 | ForEach-Object {
            if ($_ -match "EncodedCommand|IEX|DownloadString|bypass|Invoke-Expression|WebClient") {
                Write-Host "  [SUSPICIOUS] $_" -ForegroundColor Red
            } else {
                Write-Host "  $_"
            }
        }
    }
}

# ----------------------------------------------------------
Write-Host "[6] PREFETCH FILES (recently executed programs)" -ForegroundColor Cyan
# ----------------------------------------------------------
# Prefetch shows what executed even if binary was deleted
if (Test-Path "C:\Windows\Prefetch") {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 30 |
        Select-Object Name, LastWriteTime,
            @{N="Size(KB)";E={[math]::Round($_.Length/1KB,1)}} |
        Format-Table -AutoSize
} else {
    Write-Host "  Prefetch disabled or inaccessible." -ForegroundColor DarkYellow
}

# ----------------------------------------------------------
Write-Host "[7] INVESTIGATE SPECIFIC FILE" -ForegroundColor Cyan
# ----------------------------------------------------------
if ($TargetFile -and (Test-Path $TargetFile)) {
    $file = Get-Item $TargetFile
    $hash = Get-FileHash -Path $TargetFile -Algorithm SHA256
    $sig  = Get-AuthenticodeSignature -FilePath $TargetFile -EA SilentlyContinue
    $zone = Get-Content -Path $TargetFile -Stream Zone.Identifier -EA SilentlyContinue

    [PSCustomObject]@{
        Path        = $TargetFile
        SHA256      = $hash.Hash
        MD5         = (Get-FileHash -Path $TargetFile -Algorithm MD5).Hash
        Size        = "$([math]::Round($file.Length/1KB,1)) KB"
        Created     = $file.CreationTime
        Modified    = $file.LastWriteTime
        Signature   = $sig.Status
        SignedBy    = $sig.SignerCertificate.Subject
        DownloadZone= $zone
    } | Format-List

    Write-Host "  Submit SHA256 to VirusTotal: https://www.virustotal.com/gui/file/$($hash.Hash)" -ForegroundColor Yellow
} else {
    Write-Host "  No target file specified. Run with: .\05_FileInvestigation.ps1 -TargetFile 'C:\path\to\file.exe'" -ForegroundColor DarkYellow
}

Write-Host "`n[FILE DONE] => Run 06_LogCollection.ps1 next`n" -ForegroundColor Green
