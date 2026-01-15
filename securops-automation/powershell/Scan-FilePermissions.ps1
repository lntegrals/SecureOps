<#
.SYNOPSIS
    File Permission Scanner - Scans directories for permission issues.

.DESCRIPTION
    This script scans specified directories and identifies permission issues including:
    - Folders with excessive permissions (Everyone, Authenticated Users with write)
    - Broken inheritance
    - Orphaned SIDs
    - Unusual permission assignments

.PARAMETER Path
    Directory path to scan. Default: Current directory

.PARAMETER Depth
    Maximum depth to scan. Default: 3

.PARAMETER OutputPath
    Path to export JSON results. Default: ./permission-scan.json

.PARAMETER IncludeFiles
    Include individual files in scan (slower)

.EXAMPLE
    .\Scan-FilePermissions.ps1 -Path "C:\Shares" -Depth 5 -OutputPath "C:\Reports\permissions.json"

.NOTES
    Author: SecurOps Automation Suite
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Path = ".",
    
    [Parameter()]
    [int]$Depth = 3,
    
    [Parameter()]
    [string]$OutputPath = ".\permission-scan.json",
    
    [Parameter()]
    [switch]$IncludeFiles
)

# Risky identities that shouldn't have write access
$RiskyIdentities = @(
    "Everyone",
    "BUILTIN\Users",
    "NT AUTHORITY\Authenticated Users",
    "ANONYMOUS LOGON"
)

# Risky permission combinations
$RiskyPermissions = @(
    "FullControl",
    "Modify",
    "Write",
    "WriteData",
    "CreateFiles",
    "AppendData",
    "CreateDirectories",
    "ChangePermissions",
    "TakeOwnership"
)

function Test-RiskyPermission {
    [CmdletBinding()]
    param(
        [System.Security.AccessControl.FileSystemAccessRule]$AccessRule
    )
    
    $identity = $AccessRule.IdentityReference.Value
    $rights = $AccessRule.FileSystemRights.ToString()
    
    # Check if identity is risky
    $isRiskyIdentity = $RiskyIdentities | Where-Object { $identity -like "*$_*" }
    
    if (-not $isRiskyIdentity) {
        return $null
    }
    
    # Check if permissions are risky
    $hasRiskyPermission = $RiskyPermissions | Where-Object { $rights -match $_ }
    
    if ($hasRiskyPermission -and $AccessRule.AccessControlType -eq 'Allow') {
        return @{
            Identity = $identity
            Rights = $rights
            Type = $AccessRule.AccessControlType.ToString()
            Inherited = $AccessRule.IsInherited
            Risk = "HighRiskPermission"
        }
    }
    
    return $null
}

function Test-OrphanedSID {
    [CmdletBinding()]
    param(
        [System.Security.AccessControl.FileSystemAccessRule]$AccessRule
    )
    
    $identity = $AccessRule.IdentityReference.Value
    
    # Check for orphaned SIDs (S-1-5-21-... pattern without resolution)
    if ($identity -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
        return @{
            Identity = $identity
            Rights = $AccessRule.FileSystemRights.ToString()
            Type = $AccessRule.AccessControlType.ToString()
            Risk = "OrphanedSID"
        }
    }
    
    return $null
}

function Get-DirectoryPermissionIssues {
    [CmdletBinding()]
    param(
        [string]$DirectoryPath
    )
    
    $issues = @()
    
    try {
        $acl = Get-Acl -Path $DirectoryPath -ErrorAction Stop
        
        # Check for broken inheritance
        if ($acl.AreAccessRulesProtected) {
            $issues += @{
                Path = $DirectoryPath
                Issue = "BrokenInheritance"
                Details = "Access rules inheritance is disabled"
                Severity = "Warning"
            }
        }
        
        # Check each access rule
        foreach ($rule in $acl.Access) {
            # Check for risky permissions
            $riskyPerm = Test-RiskyPermission -AccessRule $rule
            if ($riskyPerm) {
                $issues += @{
                    Path = $DirectoryPath
                    Issue = $riskyPerm.Risk
                    Details = "Identity '$($riskyPerm.Identity)' has '$($riskyPerm.Rights)'"
                    Severity = "High"
                    Identity = $riskyPerm.Identity
                    Rights = $riskyPerm.Rights
                    Inherited = $riskyPerm.Inherited
                }
            }
            
            # Check for orphaned SIDs
            $orphaned = Test-OrphanedSID -AccessRule $rule
            if ($orphaned) {
                $issues += @{
                    Path = $DirectoryPath
                    Issue = $orphaned.Risk
                    Details = "Orphaned SID found: $($orphaned.Identity)"
                    Severity = "Medium"
                    Identity = $orphaned.Identity
                }
            }
        }
        
        # Check owner
        $owner = $acl.Owner
        if ($owner -match '^S-1-5-21-') {
            $issues += @{
                Path = $DirectoryPath
                Issue = "OrphanedOwner"
                Details = "Owner is an orphaned SID: $owner"
                Severity = "Medium"
            }
        }
    }
    catch {
        $issues += @{
            Path = $DirectoryPath
            Issue = "AccessDenied"
            Details = $_.Exception.Message
            Severity = "Info"
        }
    }
    
    return $issues
}

function Invoke-PermissionScan {
    [CmdletBinding()]
    param(
        [string]$ScanPath,
        [int]$MaxDepth,
        [bool]$ScanFiles
    )
    
    $results = @{
        ScanPath = (Resolve-Path $ScanPath).Path
        ScanTime = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        Computer = $env:COMPUTERNAME
        Issues = @()
        Summary = @{
            TotalScanned = 0
            IssuesFound = 0
            BySeverity = @{}
            ByIssueType = @{}
        }
    }
    
    Write-Host "`n[SecurOps] File Permission Scanner" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor DarkGray
    Write-Host "Scanning: $($results.ScanPath)" -ForegroundColor Gray
    Write-Host "Max Depth: $MaxDepth" -ForegroundColor Gray
    Write-Host "Include Files: $ScanFiles" -ForegroundColor Gray
    Write-Host ""
    
    $items = if ($ScanFiles) {
        Get-ChildItem -Path $ScanPath -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue
    } else {
        Get-ChildItem -Path $ScanPath -Recurse -Depth $MaxDepth -Directory -ErrorAction SilentlyContinue
    }
    
    $total = ($items | Measure-Object).Count
    $current = 0
    
    foreach ($item in $items) {
        $current++
        $percentComplete = [math]::Round(($current / [math]::Max($total, 1)) * 100)
        
        Write-Progress -Activity "Scanning permissions" -Status "$current of $total" -PercentComplete $percentComplete
        
        $issues = Get-DirectoryPermissionIssues -DirectoryPath $item.FullName
        $results.Issues += $issues
        $results.Summary.TotalScanned++
    }
    
    Write-Progress -Activity "Scanning permissions" -Completed
    
    # Calculate summary
    $results.Summary.IssuesFound = $results.Issues.Count
    
    $results.Issues | Group-Object Severity | ForEach-Object {
        $results.Summary.BySeverity[$_.Name] = $_.Count
    }
    
    $results.Issues | Group-Object Issue | ForEach-Object {
        $results.Summary.ByIssueType[$_.Name] = $_.Count
    }
    
    return $results
}

# Main execution
$scanResults = Invoke-PermissionScan -ScanPath $Path -MaxDepth $Depth -ScanFiles $IncludeFiles.IsPresent

# Display summary
Write-Host "`n[Summary]" -ForegroundColor Cyan
Write-Host "-" * 30 -ForegroundColor DarkGray
Write-Host "Total Scanned: $($scanResults.Summary.TotalScanned)" -ForegroundColor White
Write-Host "Issues Found: $($scanResults.Summary.IssuesFound)" -ForegroundColor $(if ($scanResults.Summary.IssuesFound -gt 0) { "Yellow" } else { "Green" })

if ($scanResults.Summary.BySeverity.Count -gt 0) {
    Write-Host "`nBy Severity:" -ForegroundColor Yellow
    $scanResults.Summary.BySeverity.GetEnumerator() | Sort-Object { 
        switch ($_.Key) { "High" { 0 } "Medium" { 1 } "Warning" { 2 } default { 3 } }
    } | ForEach-Object {
        $color = switch ($_.Key) {
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Warning" { "DarkYellow" }
            default { "Gray" }
        }
        Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor $color
    }
}

if ($scanResults.Summary.ByIssueType.Count -gt 0) {
    Write-Host "`nBy Issue Type:" -ForegroundColor Yellow
    $scanResults.Summary.ByIssueType.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Gray
    }
}

# Export results
$scanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n[+] Results exported to: $OutputPath" -ForegroundColor Green

Write-Host "`n[SecurOps] Scan complete.`n" -ForegroundColor Cyan
