<#
.SYNOPSIS
    Security Event Log Analyzer - Parses Windows Security Event Log for critical events.

.DESCRIPTION
    This script analyzes Windows Security Event logs to identify critical security events
    such as failed logins, privilege escalations, account changes, and policy modifications.
    Results are exported to JSON for dashboard integration.

.PARAMETER Hours
    Number of hours to look back in event log. Default: 24

.PARAMETER OutputPath
    Path to export JSON results. Default: ./security-events.json

.PARAMETER Critical
    Only show critical/high severity events

.EXAMPLE
    .\Audit-SecurityEvents.ps1 -Hours 48 -OutputPath "C:\Reports\security.json"

.NOTES
    Author: SecurOps Automation Suite
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Hours = 24,
    
    [Parameter()]
    [string]$OutputPath = ".\security-events.json",
    
    [Parameter()]
    [switch]$Critical
)

# Critical Event IDs to monitor
$CriticalEventIds = @{
    # Logon Events
    4624 = @{ Category = "Logon"; Severity = "Info"; Description = "Successful logon" }
    4625 = @{ Category = "Logon"; Severity = "Warning"; Description = "Failed logon attempt" }
    4648 = @{ Category = "Logon"; Severity = "Warning"; Description = "Logon using explicit credentials" }
    4634 = @{ Category = "Logon"; Severity = "Info"; Description = "Account logged off" }
    
    # Account Management
    4720 = @{ Category = "Account"; Severity = "Critical"; Description = "User account created" }
    4722 = @{ Category = "Account"; Severity = "Warning"; Description = "User account enabled" }
    4723 = @{ Category = "Account"; Severity = "Warning"; Description = "Password change attempted" }
    4724 = @{ Category = "Account"; Severity = "Warning"; Description = "Password reset attempted" }
    4725 = @{ Category = "Account"; Severity = "Warning"; Description = "User account disabled" }
    4726 = @{ Category = "Account"; Severity = "Critical"; Description = "User account deleted" }
    4738 = @{ Category = "Account"; Severity = "Warning"; Description = "User account changed" }
    
    # Privilege Use
    4672 = @{ Category = "Privilege"; Severity = "Warning"; Description = "Special privileges assigned" }
    4673 = @{ Category = "Privilege"; Severity = "Warning"; Description = "Privileged service called" }
    4674 = @{ Category = "Privilege"; Severity = "Warning"; Description = "Operation attempted on privileged object" }
    
    # Policy Changes
    4719 = @{ Category = "Policy"; Severity = "Critical"; Description = "System audit policy changed" }
    4739 = @{ Category = "Policy"; Severity = "Critical"; Description = "Domain Policy changed" }
    
    # Security State Changes
    4608 = @{ Category = "System"; Severity = "Info"; Description = "Windows starting up" }
    4616 = @{ Category = "System"; Severity = "Warning"; Description = "System time changed" }
    4697 = @{ Category = "System"; Severity = "Critical"; Description = "Service installed" }
}

function Get-SecurityEvents {
    [CmdletBinding()]
    param(
        [int]$LookbackHours,
        [hashtable]$EventDefinitions,
        [bool]$CriticalOnly
    )
    
    $startTime = (Get-Date).AddHours(-$LookbackHours)
    $events = @()
    
    Write-Host "`n[SecurOps] Security Event Log Analyzer" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor DarkGray
    Write-Host "Scanning events from: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    Write-Host "Event IDs monitored: $($EventDefinitions.Keys.Count)" -ForegroundColor Gray
    
    try {
        $filterHash = @{
            LogName = 'Security'
            StartTime = $startTime
            Id = $EventDefinitions.Keys
        }
        
        $rawEvents = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue
        
        if (-not $rawEvents) {
            Write-Host "`n[!] No security events found in the specified timeframe." -ForegroundColor Yellow
            return $events
        }
        
        Write-Host "Found $($rawEvents.Count) events to process..." -ForegroundColor Gray
        
        foreach ($event in $rawEvents) {
            $eventDef = $EventDefinitions[$event.Id]
            
            if ($CriticalOnly -and $eventDef.Severity -notin @('Critical', 'Warning')) {
                continue
            }
            
            $eventData = @{
                Timestamp = $event.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                EventId = $event.Id
                Category = $eventDef.Category
                Severity = $eventDef.Severity
                Description = $eventDef.Description
                Message = $event.Message -replace "`r`n", " " | Select-Object -First 500
                Computer = $event.MachineName
                UserId = $event.UserId.Value
                RecordId = $event.RecordId
            }
            
            $events += [PSCustomObject]$eventData
        }
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve security events: $_" -ForegroundColor Red
        Write-Host "Note: This script requires administrative privileges to access Security log." -ForegroundColor Yellow
    }
    
    return $events
}

function Format-EventSummary {
    [CmdletBinding()]
    param(
        [array]$Events
    )
    
    $summary = @{
        TotalEvents = $Events.Count
        ByCategory = @{}
        BySeverity = @{}
        TopEvents = @()
    }
    
    # Group by category
    $Events | Group-Object Category | ForEach-Object {
        $summary.ByCategory[$_.Name] = $_.Count
    }
    
    # Group by severity
    $Events | Group-Object Severity | ForEach-Object {
        $summary.BySeverity[$_.Name] = $_.Count
    }
    
    # Top 5 most frequent events
    $summary.TopEvents = $Events | 
        Group-Object EventId | 
        Sort-Object Count -Descending | 
        Select-Object -First 5 | 
        ForEach-Object {
            @{
                EventId = $_.Name
                Count = $_.Count
                Description = $CriticalEventIds[[int]$_.Name].Description
            }
        }
    
    return $summary
}

function Export-Results {
    [CmdletBinding()]
    param(
        [array]$Events,
        [hashtable]$Summary,
        [string]$Path
    )
    
    $output = @{
        GeneratedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        Computer = $env:COMPUTERNAME
        LookbackHours = $Hours
        Summary = $Summary
        Events = $Events
    }
    
    $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "`n[+] Results exported to: $Path" -ForegroundColor Green
}

# Main execution
$securityEvents = Get-SecurityEvents -LookbackHours $Hours -EventDefinitions $CriticalEventIds -CriticalOnly $Critical.IsPresent
$summary = Format-EventSummary -Events $securityEvents

# Display summary
Write-Host "`n[Summary]" -ForegroundColor Cyan
Write-Host "-" * 30 -ForegroundColor DarkGray
Write-Host "Total Events: $($summary.TotalEvents)" -ForegroundColor White

Write-Host "`nBy Severity:" -ForegroundColor Yellow
$summary.BySeverity.GetEnumerator() | ForEach-Object {
    $color = switch ($_.Key) {
        "Critical" { "Red" }
        "Warning" { "Yellow" }
        default { "Gray" }
    }
    Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor $color
}

Write-Host "`nBy Category:" -ForegroundColor Yellow
$summary.ByCategory.GetEnumerator() | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Gray
}

# Export results
Export-Results -Events $securityEvents -Summary $summary -Path $OutputPath

Write-Host "`n[SecurOps] Audit complete.`n" -ForegroundColor Cyan
