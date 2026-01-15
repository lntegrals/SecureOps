<#
.SYNOPSIS
    Permission Auditor - Audits user and group permissions across systems.

.DESCRIPTION
    This script audits permissions and access rights including:
    - Local user and group memberships
    - Privileged group membership analysis
    - Stale account detection
    - Permission inheritance review
    - Access rights report generation

.PARAMETER Scope
    Scope of audit: Users, Groups, All

.PARAMETER IncludeDisabled
    Include disabled accounts in the audit

.PARAMETER PrivilegedOnly
    Only report on privileged/admin accounts

.PARAMETER MaxInactiveDays
    Number of days to consider an account stale. Default: 90

.PARAMETER OutputPath
    Path to export audit report. Default: ./permission-audit.json

.EXAMPLE
    .\Audit-Permissions.ps1 -Scope All -PrivilegedOnly -OutputPath "C:\Reports\permissions.json"

.NOTES
    Author: IdentityOps Automation Suite
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Users", "Groups", "All")]
    [string]$Scope = "All",
    
    [Parameter()]
    [switch]$IncludeDisabled,
    
    [Parameter()]
    [switch]$PrivilegedOnly,
    
    [Parameter()]
    [int]$MaxInactiveDays = 90,
    
    [Parameter()]
    [string]$OutputPath = ".\permission-audit.json"
)

# Privileged group definitions
$PrivilegedGroups = @(
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Backup Operators",
    "Server Operators",
    "Account Operators",
    "Remote Desktop Users",
    "Power Users",
    "Hyper-V Administrators"
)

# Risk levels for groups
$GroupRiskLevels = @{
    "Administrators" = "Critical"
    "Domain Admins" = "Critical"
    "Enterprise Admins" = "Critical"
    "Schema Admins" = "Critical"
    "Backup Operators" = "High"
    "Server Operators" = "High"
    "Account Operators" = "High"
    "Remote Desktop Users" = "Medium"
    "Power Users" = "Medium"
    "Hyper-V Administrators" = "Medium"
}

# Audit results
$AuditResults = @{
    GeneratedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    Computer = $env:COMPUTERNAME
    Scope = $Scope
    Summary = @{
        TotalUsers = 0
        TotalGroups = 0
        PrivilegedUsers = 0
        StaleAccounts = 0
        DisabledAccounts = 0
        Issues = 0
    }
    Users = @()
    Groups = @()
    Issues = @()
    Recommendations = @()
}

function Get-UserPermissionProfile {
    [CmdletBinding()]
    param(
        [System.Security.Principal.SecurityIdentifier]$UserSID,
        [string]$Username
    )
    
    $profile = @{
        Username = $Username
        SID = $UserSID.Value
        Groups = @()
        PrivilegedGroups = @()
        RiskLevel = "Low"
        Enabled = $true
        LastLogon = $null
        IsStale = $false
        PasswordLastSet = $null
        PasswordNeverExpires = $false
        Issues = @()
    }
    
    try {
        $localUser = Get-LocalUser -Name $Username -ErrorAction Stop
        
        $profile.Enabled = $localUser.Enabled
        $profile.LastLogon = $localUser.LastLogon
        $profile.PasswordLastSet = $localUser.PasswordLastSet
        $profile.PasswordNeverExpires = $localUser.PasswordNeverExpires
        
        # Check if stale
        if ($localUser.LastLogon) {
            $daysSinceLogon = ((Get-Date) - $localUser.LastLogon).Days
            if ($daysSinceLogon -gt $MaxInactiveDays) {
                $profile.IsStale = $true
                $profile.Issues += @{
                    Type = "StaleAccount"
                    Severity = "Medium"
                    Details = "Last logon was $daysSinceLogon days ago"
                }
            }
        }
        
        # Check password issues
        if ($profile.PasswordNeverExpires -and $profile.Enabled) {
            $profile.Issues += @{
                Type = "PasswordNeverExpires"
                Severity = "Medium"
                Details = "Password is set to never expire for enabled account"
            }
        }
    }
    catch {
        $profile.Issues += @{
            Type = "ProfileError"
            Severity = "Info"
            Details = "Could not retrieve full user details"
        }
    }
    
    # Get group memberships
    try {
        $groups = Get-LocalGroup | Where-Object {
            try {
                $members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
                $members.Name -contains $Username -or $members.SID -contains $UserSID
            }
            catch { $false }
        }
        
        foreach ($group in $groups) {
            $profile.Groups += $group.Name
            
            if ($PrivilegedGroups -contains $group.Name) {
                $profile.PrivilegedGroups += $group.Name
                $risk = $GroupRiskLevels[$group.Name]
                
                # Update risk level to highest
                if ($risk -eq "Critical" -or $profile.RiskLevel -eq "Low") {
                    $profile.RiskLevel = $risk
                }
                elseif ($risk -eq "High" -and $profile.RiskLevel -ne "Critical") {
                    $profile.RiskLevel = $risk
                }
            }
        }
    }
    catch {
        $profile.Issues += @{
            Type = "GroupEnumerationError"
            Severity = "Warning"
            Details = $_.Exception.Message
        }
    }
    
    return $profile
}

function Get-GroupAuditProfile {
    [CmdletBinding()]
    param(
        [Microsoft.PowerShell.Commands.LocalGroup]$Group
    )
    
    $profile = @{
        Name = $Group.Name
        SID = $Group.SID.Value
        Description = $Group.Description
        IsPrivileged = $PrivilegedGroups -contains $Group.Name
        RiskLevel = $GroupRiskLevels[$Group.Name] ?? "Low"
        MemberCount = 0
        Members = @()
        Issues = @()
    }
    
    try {
        $members = Get-LocalGroupMember -Group $Group.Name -ErrorAction SilentlyContinue
        $profile.MemberCount = ($members | Measure-Object).Count
        
        foreach ($member in $members) {
            $memberInfo = @{
                Name = $member.Name
                SID = $member.SID.Value
                ObjectClass = $member.ObjectClass
            }
            $profile.Members += $memberInfo
        }
        
        # Check for issues
        if ($profile.IsPrivileged -and $profile.MemberCount -gt 5) {
            $profile.Issues += @{
                Type = "ExcessivePrivilegedMembers"
                Severity = "Warning"
                Details = "Privileged group has $($profile.MemberCount) members, consider reducing"
            }
        }
        
        if ($profile.IsPrivileged -and $profile.MemberCount -eq 0) {
            $profile.Issues += @{
                Type = "EmptyPrivilegedGroup"
                Severity = "Info"
                Details = "Privileged group has no members"
            }
        }
    }
    catch {
        $profile.Issues += @{
            Type = "MemberEnumerationError"
            Severity = "Warning"
            Details = $_.Exception.Message
        }
    }
    
    return $profile
}

function Add-AuditIssue {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$Source,
        [string]$Details
    )
    
    $AuditResults.Issues += @{
        Type = $Type
        Severity = $Severity
        Source = $Source
        Details = $Details
        DetectedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
    $AuditResults.Summary.Issues++
}

function Add-Recommendation {
    param(
        [string]$Category,
        [string]$Priority,
        [string]$Recommendation
    )
    
    $AuditResults.Recommendations += @{
        Category = $Category
        Priority = $Priority
        Recommendation = $Recommendation
    }
}

# Main execution
Write-Host "`n[IdentityOps] Permission Auditor" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor DarkGray
Write-Host "Scope: $Scope" -ForegroundColor Gray
Write-Host "Include Disabled: $IncludeDisabled" -ForegroundColor Gray
Write-Host "Privileged Only: $PrivilegedOnly" -ForegroundColor Gray
Write-Host "Stale Threshold: $MaxInactiveDays days" -ForegroundColor Gray
Write-Host ""

# Audit Users
if ($Scope -in @("Users", "All")) {
    Write-Host "[*] Auditing users..." -ForegroundColor Yellow
    
    $users = Get-LocalUser
    if (-not $IncludeDisabled) {
        $users = $users | Where-Object { $_.Enabled }
    }
    
    $userCount = ($users | Measure-Object).Count
    $current = 0
    
    foreach ($user in $users) {
        $current++
        Write-Progress -Activity "Auditing users" -Status "$current of $userCount" -PercentComplete (($current / $userCount) * 100)
        
        $profile = Get-UserPermissionProfile -UserSID $user.SID -Username $user.Name
        
        # Skip non-privileged if PrivilegedOnly
        if ($PrivilegedOnly -and $profile.PrivilegedGroups.Count -eq 0) {
            continue
        }
        
        $AuditResults.Users += $profile
        $AuditResults.Summary.TotalUsers++
        
        if ($profile.PrivilegedGroups.Count -gt 0) {
            $AuditResults.Summary.PrivilegedUsers++
        }
        
        if ($profile.IsStale) {
            $AuditResults.Summary.StaleAccounts++
            Add-AuditIssue -Type "StaleAccount" -Severity "Medium" -Source $user.Name -Details "Account inactive for over $MaxInactiveDays days"
        }
        
        if (-not $profile.Enabled) {
            $AuditResults.Summary.DisabledAccounts++
        }
        
        # Check for concerning combinations
        if ($profile.PrivilegedGroups.Count -gt 2) {
            Add-AuditIssue -Type "ExcessivePrivileges" -Severity "High" -Source $user.Name -Details "User is member of $($profile.PrivilegedGroups.Count) privileged groups: $($profile.PrivilegedGroups -join ', ')"
        }
    }
    
    Write-Progress -Activity "Auditing users" -Completed
}

# Audit Groups
if ($Scope -in @("Groups", "All")) {
    Write-Host "[*] Auditing groups..." -ForegroundColor Yellow
    
    $groups = Get-LocalGroup
    if ($PrivilegedOnly) {
        $groups = $groups | Where-Object { $PrivilegedGroups -contains $_.Name }
    }
    
    $groupCount = ($groups | Measure-Object).Count
    $current = 0
    
    foreach ($group in $groups) {
        $current++
        Write-Progress -Activity "Auditing groups" -Status "$current of $groupCount" -PercentComplete (($current / $groupCount) * 100)
        
        $profile = Get-GroupAuditProfile -Group $group
        $AuditResults.Groups += $profile
        $AuditResults.Summary.TotalGroups++
        
        foreach ($issue in $profile.Issues) {
            Add-AuditIssue -Type $issue.Type -Severity $issue.Severity -Source $group.Name -Details $issue.Details
        }
    }
    
    Write-Progress -Activity "Auditing groups" -Completed
}

# Generate recommendations
Write-Host "[*] Generating recommendations..." -ForegroundColor Yellow

if ($AuditResults.Summary.StaleAccounts -gt 0) {
    Add-Recommendation -Category "Account Hygiene" -Priority "High" -Recommendation "Review and disable or remove $($AuditResults.Summary.StaleAccounts) stale accounts that have not logged in for over $MaxInactiveDays days"
}

if ($AuditResults.Summary.PrivilegedUsers -gt 5) {
    Add-Recommendation -Category "Least Privilege" -Priority "High" -Recommendation "Consider reducing the number of privileged users ($($AuditResults.Summary.PrivilegedUsers)). Implement just-in-time access for administrative tasks"
}

$criticalIssues = ($AuditResults.Issues | Where-Object { $_.Severity -eq "High" -or $_.Severity -eq "Critical" }).Count
if ($criticalIssues -gt 0) {
    Add-Recommendation -Category "Security" -Priority "Critical" -Recommendation "Address $criticalIssues high/critical priority issues immediately"
}

# Display summary
Write-Host "`n[Summary]" -ForegroundColor Cyan
Write-Host "-" * 30 -ForegroundColor DarkGray
Write-Host "Total Users Audited: $($AuditResults.Summary.TotalUsers)" -ForegroundColor White
Write-Host "Total Groups Audited: $($AuditResults.Summary.TotalGroups)" -ForegroundColor White
Write-Host "Privileged Users: $($AuditResults.Summary.PrivilegedUsers)" -ForegroundColor $(if ($AuditResults.Summary.PrivilegedUsers -gt 5) { "Yellow" } else { "Gray" })
Write-Host "Stale Accounts: $($AuditResults.Summary.StaleAccounts)" -ForegroundColor $(if ($AuditResults.Summary.StaleAccounts -gt 0) { "Yellow" } else { "Gray" })
Write-Host "Issues Found: $($AuditResults.Summary.Issues)" -ForegroundColor $(if ($AuditResults.Summary.Issues -gt 0) { "Yellow" } else { "Green" })

if ($AuditResults.Issues.Count -gt 0) {
    Write-Host "`n[Issues]" -ForegroundColor Yellow
    $AuditResults.Issues | Group-Object Severity | Sort-Object { 
        switch ($_.Name) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } default { 3 } }
    } | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $(
            switch ($_.Name) { "Critical" { "Red" } "High" { "Red" } "Medium" { "Yellow" } default { "Gray" } }
        )
    }
}

if ($AuditResults.Recommendations.Count -gt 0) {
    Write-Host "`n[Recommendations]" -ForegroundColor Cyan
    foreach ($rec in $AuditResults.Recommendations) {
        $color = switch ($rec.Priority) { "Critical" { "Red" } "High" { "Yellow" } default { "Gray" } }
        Write-Host "  [$($rec.Priority)] $($rec.Recommendation)" -ForegroundColor $color
    }
}

# Export results
$AuditResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n[+] Audit report exported to: $OutputPath" -ForegroundColor Green

Write-Host "`n[IdentityOps] Audit complete.`n" -ForegroundColor Cyan
