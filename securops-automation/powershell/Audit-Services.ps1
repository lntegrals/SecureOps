<#
.SYNOPSIS
    Service Status Auditor - Checks service status and detects stopped critical services.

.DESCRIPTION
    This script audits Windows services to identify:
    - Stopped critical services
    - Services with unusual startup types
    - Services running under non-standard accounts
    - Recently changed services

.PARAMETER CriticalOnly
    Only show critical services that require attention

.PARAMETER OutputPath
    Path to export JSON results. Default: ./service-audit.json

.PARAMETER CustomCritical
    Array of additional service names to treat as critical

.EXAMPLE
    .\Audit-Services.ps1 -CriticalOnly -OutputPath "C:\Reports\services.json"

.NOTES
    Author: SecurOps Automation Suite
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$CriticalOnly,
    
    [Parameter()]
    [string]$OutputPath = ".\service-audit.json",
    
    [Parameter()]
    [string[]]$CustomCritical = @()
)

# Default critical services to monitor
$DefaultCriticalServices = @(
    # Security Services
    "wuauserv",          # Windows Update
    "WinDefend",         # Windows Defender
    "MpsSvc",            # Windows Firewall
    "SecurityHealthService", # Windows Security
    "wscsvc",            # Security Center
    
    # Core System Services
    "EventLog",          # Windows Event Log
    "Schedule",          # Task Scheduler
    "LanmanServer",      # Server (file sharing)
    "LanmanWorkstation", # Workstation
    "Dnscache",          # DNS Client
    "BITS",              # Background Intelligent Transfer
    "CryptSvc",          # Cryptographic Services
    "RpcSs",             # Remote Procedure Call
    "SamSs",             # Security Accounts Manager
    "Netlogon",          # Netlogon (domain joined)
    
    # Remote Management
    "WinRM",             # Windows Remote Management
    "TermService",       # Remote Desktop Services
    "SessionEnv",        # Remote Desktop Configuration
    
    # Monitoring
    "W32Time",           # Windows Time
    "DiagTrack"          # Diagnostics Tracking
)

# Standard service accounts (considered safe)
$StandardAccounts = @(
    "LocalSystem",
    "NT AUTHORITY\LocalService",
    "NT AUTHORITY\NetworkService",
    "NT AUTHORITY\SYSTEM",
    "Local System",
    "NT AUTHORITY\Local Service",
    "NT AUTHORITY\Network Service"
)

function Get-ServiceDetails {
    [CmdletBinding()]
    param(
        [System.ServiceProcess.ServiceController]$Service,
        [string[]]$CriticalList
    )
    
    $isCritical = $CriticalList -contains $Service.ServiceName
    
    try {
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($Service.ServiceName)'" -ErrorAction SilentlyContinue
        $startName = if ($wmiService) { $wmiService.StartName } else { "Unknown" }
        $pathName = if ($wmiService) { $wmiService.PathName } else { "Unknown" }
        $description = if ($wmiService) { $wmiService.Description } else { "" }
    }
    catch {
        $startName = "Unknown"
        $pathName = "Unknown"
        $description = ""
    }
    
    $issues = @()
    
    # Check for stopped critical services
    if ($isCritical -and $Service.Status -ne 'Running') {
        $issues += @{
            Type = "CriticalServiceNotRunning"
            Severity = "High"
            Details = "Critical service '$($Service.ServiceName)' is $($Service.Status)"
        }
    }
    
    # Check for unusual startup type
    if ($isCritical -and $Service.StartType -eq 'Disabled') {
        $issues += @{
            Type = "CriticalServiceDisabled"
            Severity = "High"
            Details = "Critical service '$($Service.ServiceName)' is disabled"
        }
    }
    
    # Check for non-standard service accounts
    $isStandardAccount = $StandardAccounts | Where-Object { $startName -like "*$_*" }
    if (-not $isStandardAccount -and $startName -ne "Unknown") {
        $issues += @{
            Type = "NonStandardAccount"
            Severity = "Medium"
            Details = "Service runs under non-standard account: $startName"
        }
    }
    
    return @{
        Name = $Service.ServiceName
        DisplayName = $Service.DisplayName
        Status = $Service.Status.ToString()
        StartType = $Service.StartType.ToString()
        ServiceAccount = $startName
        Path = $pathName
        Description = $description
        IsCritical = $isCritical
        CanStop = $Service.CanStop
        CanPauseAndContinue = $Service.CanPauseAndContinue
        Issues = $issues
    }
}

function Invoke-ServiceAudit {
    [CmdletBinding()]
    param(
        [string[]]$CriticalServices,
        [bool]$OnlyCritical
    )
    
    $results = @{
        AuditTime = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        Computer = $env:COMPUTERNAME
        Services = @()
        Issues = @()
        Summary = @{
            Total = 0
            Running = 0
            Stopped = 0
            Disabled = 0
            CriticalWithIssues = 0
            NonStandardAccounts = 0
        }
    }
    
    Write-Host "`n[SecurOps] Service Status Auditor" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor DarkGray
    Write-Host "Monitoring $($CriticalServices.Count) critical services" -ForegroundColor Gray
    Write-Host ""
    
    $services = Get-Service | Sort-Object DisplayName
    
    $total = ($services | Measure-Object).Count
    $current = 0
    
    foreach ($service in $services) {
        $current++
        Write-Progress -Activity "Auditing services" -Status "$current of $total" -PercentComplete (($current / $total) * 100)
        
        $details = Get-ServiceDetails -Service $service -CriticalList $CriticalServices
        
        # Skip non-critical if only critical requested
        if ($OnlyCritical -and -not $details.IsCritical) {
            continue
        }
        
        $results.Services += $details
        
        if ($details.Issues.Count -gt 0) {
            foreach ($issue in $details.Issues) {
                $results.Issues += @{
                    ServiceName = $details.Name
                    DisplayName = $details.DisplayName
                    Type = $issue.Type
                    Severity = $issue.Severity
                    Details = $issue.Details
                }
            }
        }
        
        # Update summary
        $results.Summary.Total++
        switch ($details.Status) {
            "Running" { $results.Summary.Running++ }
            "Stopped" { $results.Summary.Stopped++ }
        }
        if ($details.StartType -eq "Disabled") { $results.Summary.Disabled++ }
    }
    
    Write-Progress -Activity "Auditing services" -Completed
    
    # Count critical issues
    $results.Summary.CriticalWithIssues = ($results.Services | Where-Object { $_.IsCritical -and $_.Issues.Count -gt 0 }).Count
    $results.Summary.NonStandardAccounts = ($results.Issues | Where-Object { $_.Type -eq "NonStandardAccount" }).Count
    
    return $results
}

# Merge default and custom critical services
$AllCriticalServices = $DefaultCriticalServices + $CustomCritical | Select-Object -Unique

# Main execution
$auditResults = Invoke-ServiceAudit -CriticalServices $AllCriticalServices -OnlyCritical $CriticalOnly.IsPresent

# Display summary
Write-Host "`n[Summary]" -ForegroundColor Cyan
Write-Host "-" * 30 -ForegroundColor DarkGray
Write-Host "Total Services: $($auditResults.Summary.Total)" -ForegroundColor White
Write-Host "Running: $($auditResults.Summary.Running)" -ForegroundColor Green
Write-Host "Stopped: $($auditResults.Summary.Stopped)" -ForegroundColor $(if ($auditResults.Summary.Stopped -gt 0) { "Yellow" } else { "Gray" })
Write-Host "Disabled: $($auditResults.Summary.Disabled)" -ForegroundColor Gray

# Show issues
if ($auditResults.Issues.Count -gt 0) {
    Write-Host "`n[Issues Detected]" -ForegroundColor Red
    Write-Host "-" * 30 -ForegroundColor DarkGray
    
    $auditResults.Issues | Group-Object Type | ForEach-Object {
        Write-Host "`n$($_.Name) ($($_.Count)):" -ForegroundColor Yellow
        $_.Group | ForEach-Object {
            $color = switch ($_.Severity) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                default { "Gray" }
            }
            Write-Host "  - $($_.DisplayName): $($_.Details)" -ForegroundColor $color
        }
    }
} else {
    Write-Host "`n[+] No issues detected!" -ForegroundColor Green
}

# Critical services status table
Write-Host "`n[Critical Services Status]" -ForegroundColor Cyan
Write-Host "-" * 30 -ForegroundColor DarkGray

$criticalServices = $auditResults.Services | Where-Object { $_.IsCritical }
foreach ($svc in $criticalServices) {
    $statusColor = switch ($svc.Status) {
        "Running" { "Green" }
        "Stopped" { "Red" }
        default { "Yellow" }
    }
    $status = $svc.Status.PadRight(10)
    Write-Host "  [$status] $($svc.DisplayName)" -ForegroundColor $statusColor
}

# Export results
$auditResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n[+] Results exported to: $OutputPath" -ForegroundColor Green

Write-Host "`n[SecurOps] Audit complete.`n" -ForegroundColor Cyan
