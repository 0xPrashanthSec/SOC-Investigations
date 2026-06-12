#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Analyzes Windows Audit Policy against CIS Benchmark / STIG baselines.
.DESCRIPTION
    Parses current auditpol settings, compares against a tiered baseline, outputs a
    color-coded console report, exports a CSV, and optionally generates a remediation script.
.PARAMETER WhatIf
    Run analysis and reporting only; skip generation of Fix-AuditPolicy.ps1.
.EXAMPLE
    .\Get-AuditPolicyAnalysis.ps1
    .\Get-AuditPolicyAnalysis.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Baseline Definition ────────────────────────────────────────────────

# Values: 'Success and Failure' | 'Success' | 'Failure' | 'No Auditing'
$Baseline = @{

    MUST_ENABLE = @{
        # Logon / Logoff
        'Logon'                             = 'Success and Failure'
        'Logoff'                            = 'Success'
        'Account Lockout'                   = 'Success and Failure'
        'Special Logon'                     = 'Success'
        'Other Logon/Logoff Events'         = 'Success and Failure'

        # Account Management
        'User Account Management'           = 'Success and Failure'
        'Security Group Management'         = 'Success and Failure'
        'Computer Account Management'       = 'Success and Failure'
        'Distribution Group Management'     = 'Success and Failure'
        'Other Account Management Events'   = 'Success and Failure'

        # Privilege Use
        'Sensitive Privilege Use'           = 'Success and Failure'

        # Process Creation
        'Process Creation'                  = 'Success'
        'Process Termination'               = 'Success'

        # Policy Change
        'Audit Policy Change'               = 'Success and Failure'
        'Authentication Policy Change'      = 'Success and Failure'
        'Authorization Policy Change'       = 'Success and Failure'
        'MPSSVC Rule-Level Policy Change'   = 'Success and Failure'
        'Other Policy Change Events'        = 'Success and Failure'

        # System
        'Security State Change'             = 'Success and Failure'
        'Security System Extension'         = 'Success and Failure'
        'System Integrity'                  = 'Success and Failure'
        'IPsec Driver'                      = 'Success and Failure'
        'Other System Events'               = 'Success and Failure'

        # Account Logon
        'Credential Validation'             = 'Success and Failure'
        'Kerberos Service Ticket Operations'= 'Success and Failure'
        'Kerberos Authentication Service'   = 'Success and Failure'
        'Other Account Logon Events'        = 'Success and Failure'
    }

    CONDITIONAL = @{
        # Object Access — enable if file-server / DLP scope
        'File System'                       = 'Success and Failure'
        'Registry'                          = 'Success and Failure'
        'Kernel Object'                     = 'Success and Failure'
        'SAM'                               = 'Success and Failure'
        'Certification Services'            = 'Success and Failure'
        'Handle Manipulation'               = 'Success and Failure'
        'File Share'                        = 'Success and Failure'
        'Detailed File Share'               = 'Failure'
        'Other Object Access Events'        = 'Success and Failure'
        'Removable Storage'                 = 'Success and Failure'
        'Central Access Policy Staging'     = 'Failure'

        # DS Access — enable on Domain Controllers
        'Directory Service Access'          = 'Failure'
        'Directory Service Changes'         = 'Success'
        'Directory Service Replication'     = 'No Auditing'
        'Detailed Directory Service Replication' = 'No Auditing'

        # Network Policy / NPS
        'Network Policy Server'             = 'Success and Failure'
    }

    NOISY_SKIP = @(
        'Filtering Platform Packet Drop'
        'Filtering Platform Connection'
        'Non Sensitive Privilege Use'
        'DPAPI Activity'
        'RPC Events'
        'Token Right Adjusted Events'
        'Application Generated'
        'Application Group Management'
    )
}

#endregion

#region ── Helpers ────────────────────────────────────────────────────────────

function Get-CurrentAuditPolicy {
    $raw = auditpol /get /category:* /r 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed: $($raw -join ' ')"
    }

    # auditpol /r outputs a header line then CSV rows
    $csvLines = $raw | Where-Object { $_ -match ',' }
    $header   = $csvLines[0]
    $data     = $csvLines[1..($csvLines.Count - 1)]

    ($header, $data) -join "`n" | ConvertFrom-Csv |
        Select-Object @{N='Category';    E={$_.'Category/Subcategory'.Trim()}},
                      @{N='Subcategory'; E={$_.'Subcategory'.Trim()}},
                      @{N='Setting';     E={$_.'Inclusion Setting'.Trim()}}
}

function Get-ComplianceStatus {
    param(
        [string]$Subcategory,
        [string]$Current,
        [hashtable]$Baseline
    )

    if ($Baseline.NOISY_SKIP -contains $Subcategory) {
        if ($Current -ne 'No Auditing') { return 'OVER_AUDITED' }
        return 'COMPLIANT'
    }

    $recommended = $null
    if ($Baseline.MUST_ENABLE.ContainsKey($Subcategory)) {
        $recommended = $Baseline.MUST_ENABLE[$Subcategory]
    } elseif ($Baseline.CONDITIONAL.ContainsKey($Subcategory)) {
        $recommended = $Baseline.CONDITIONAL[$Subcategory]
    } else {
        return 'UNKNOWN'
    }

    if ($Current -eq $recommended)           { return 'COMPLIANT' }
    if ($Current -eq 'No Auditing')          { return 'NOT_CONFIGURED' }
    return 'PARTIAL'
}

#endregion

#region ── Main Analysis ──────────────────────────────────────────────────────

Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║         Windows Audit Policy Analyzer  —  CIS / STIG        ║' -ForegroundColor Cyan
Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host "  Host : $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ''

Write-Host '[*] Reading current audit policy...' -ForegroundColor Cyan
$currentPolicy = Get-CurrentAuditPolicy

$results = foreach ($entry in $currentPolicy) {
    $sub    = $entry.Subcategory
    $status = Get-ComplianceStatus -Subcategory $sub -Current $entry.Setting -Baseline $Baseline

    $tier = 'NOT_IN_BASELINE'
    if ($Baseline.MUST_ENABLE.ContainsKey($sub))   { $tier = 'MUST_ENABLE' }
    elseif ($Baseline.CONDITIONAL.ContainsKey($sub)){ $tier = 'CONDITIONAL' }
    elseif ($Baseline.NOISY_SKIP -contains $sub)    { $tier = 'NOISY_SKIP' }

    $recommended = switch ($tier) {
        'MUST_ENABLE'  { $Baseline.MUST_ENABLE[$sub] }
        'CONDITIONAL'  { $Baseline.CONDITIONAL[$sub] }
        'NOISY_SKIP'   { 'No Auditing' }
        default        { 'N/A' }
    }

    [PSCustomObject]@{
        Category    = $entry.Category
        Subcategory = $sub
        Current     = $entry.Setting
        Recommended = $recommended
        Tier        = $tier
        Status      = $status
    }
}

#endregion

#region ── Console Report ─────────────────────────────────────────────────────

$grouped = $results | Group-Object Category | Sort-Object Name

foreach ($group in $grouped) {
    Write-Host ''
    Write-Host "  ── $($group.Name) ──" -ForegroundColor Cyan

    foreach ($item in $group.Group | Sort-Object Subcategory) {
        $color = switch ($item.Status) {
            'COMPLIANT'      { 'Green'  }
            'PARTIAL'        { 'Yellow' }
            'NOT_CONFIGURED' { 'Red'    }
            'OVER_AUDITED'   { 'Yellow' }
            default          { 'Gray'   }
        }

        $tag = "[$($item.Status.PadRight(14))]"
        $line = "    {0,-42} {1}  Current: {2}" -f $item.Subcategory, $tag, $item.Current
        Write-Host $line -ForegroundColor $color
    }
}

#endregion

#region ── Summary Counts ─────────────────────────────────────────────────────

Write-Host ''
Write-Host '╔══════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║           Summary            ║' -ForegroundColor Cyan
Write-Host '╚══════════════════════════════╝' -ForegroundColor Cyan

$counts = $results | Group-Object Status | Sort-Object Name
foreach ($c in $counts) {
    $color = switch ($c.Name) {
        'COMPLIANT'      { 'Green'  }
        'PARTIAL'        { 'Yellow' }
        'NOT_CONFIGURED' { 'Red'    }
        'OVER_AUDITED'   { 'Yellow' }
        default          { 'Gray'   }
    }
    Write-Host ("  {0,-18} : {1}" -f $c.Name, $c.Count) -ForegroundColor $color
}
Write-Host ''

#endregion

#region ── CSV Export ─────────────────────────────────────────────────────────

$date      = Get-Date -Format 'yyyyMMdd'
$csvPath   = Join-Path $PSScriptRoot "AuditPolicy_Report_$($env:COMPUTERNAME)_$date.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] CSV report saved : $csvPath" -ForegroundColor Green

#endregion

#region ── Remediation Script Generation ─────────────────────────────────────

if (-not $WhatIf) {
    $fixPath    = Join-Path $PSScriptRoot 'Fix-AuditPolicy.ps1'
    $fixItems   = $results | Where-Object {
        $_.Tier -eq 'MUST_ENABLE' -and $_.Status -in 'NOT_CONFIGURED', 'PARTIAL'
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('#Requires -RunAsAdministrator')
    $lines.Add('<#')
    $lines.Add('.SYNOPSIS')
    $lines.Add('    Auto-generated remediation script — apply missing MUST_ENABLE audit settings.')
    $lines.Add(".NOTES")
    $lines.Add("    Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Host : $env:COMPUTERNAME")
    $lines.Add('#>')
    $lines.Add('')
    $lines.Add('Set-StrictMode -Version Latest')
    $lines.Add('$ErrorActionPreference = ''Stop''')
    $lines.Add('')

    foreach ($item in $fixItems | Sort-Object Subcategory) {
        $flag = switch ($item.Recommended) {
            'Success and Failure' { '/success:enable /failure:enable'  }
            'Success'             { '/success:enable /failure:disable' }
            'Failure'             { '/success:disable /failure:enable' }
            default               { '/success:disable /failure:disable' }
        }
        $lines.Add("# [$($item.Status)] $($item.Subcategory) — was: $($item.Current)")
        $lines.Add("auditpol /set /subcategory:`"$($item.Subcategory)`" $flag")
        $lines.Add('')
    }

    $lines.Add("Write-Host '[+] Audit policy remediation applied.' -ForegroundColor Green")

    $lines | Set-Content -Path $fixPath -Encoding UTF8

    if ($fixItems.Count -gt 0) {
        Write-Host "[+] Remediation script saved : $fixPath  ($($fixItems.Count) item(s))" -ForegroundColor Green
    } else {
        Write-Host '[+] No MUST_ENABLE gaps found — remediation script is a no-op.' -ForegroundColor Green
    }
} else {
    Write-Host '[-] WhatIf: remediation script generation skipped.' -ForegroundColor Yellow
}

Write-Host ''

#endregion
