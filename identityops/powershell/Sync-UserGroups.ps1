<#
.SYNOPSIS
    Group Membership Synchronization - Synchronizes user group memberships.

.DESCRIPTION
    This script manages group membership synchronization including:
    - Bulk group membership updates from CSV/JSON
    - Role-based group assignment templates
    - Group membership reconciliation
    - Membership change reporting

.PARAMETER SourceFile
    Path to source file (CSV or JSON) with desired group memberships

.PARAMETER Template
    Predefined role template to apply: IT, HR, Finance, Developer, Manager

.PARAMETER Username
    Single user to synchronize groups for

.PARAMETER Groups
    Array of groups to ensure user is member of

.PARAMETER RemoveExisting
    Remove user from groups not in the specified list

.PARAMETER WhatIf
    Show what changes would be made without applying them

.PARAMETER OutputPath
    Path to export sync report. Default: ./group-sync-report.json

.EXAMPLE
    .\Sync-UserGroups.ps1 -Username "jdoe" -Template "IT" -WhatIf

.EXAMPLE
    .\Sync-UserGroups.ps1 -SourceFile ".\group-assignments.csv"

.NOTES
    Author: IdentityOps Automation Suite
    Version: 1.0.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = "File")]
    [string]$SourceFile,
    
    [Parameter(ParameterSetName = "Template")]
    [Parameter(ParameterSetName = "Manual")]
    [string]$Username,
    
    [Parameter(ParameterSetName = "Template")]
    [ValidateSet("IT", "HR", "Finance", "Developer", "Manager", "Standard")]
    [string]$Template,
    
    [Parameter(ParameterSetName = "Manual")]
    [string[]]$Groups,
    
    [Parameter()]
    [switch]$RemoveExisting,
    
    [Parameter()]
    [string]$OutputPath = ".\group-sync-report.json"
)

# Role templates with group assignments
$RoleTemplates = @{
    "Standard" = @{
        Groups = @("Users")
        Description = "Standard user with basic access"
    }
    "IT" = @{
        Groups = @("Users", "Remote Desktop Users", "IT Support")
        Description = "IT Support staff with remote access capabilities"
    }
    "HR" = @{
        Groups = @("Users", "HR Department")
        Description = "Human Resources team members"
    }
    "Finance" = @{
        Groups = @("Users", "Finance Department")
        Description = "Finance team members"
    }
    "Developer" = @{
        Groups = @("Users", "Developers", "Remote Desktop Users")
        Description = "Software developers with development resources access"
    }
    "Manager" = @{
        Groups = @("Users", "Managers", "Remote Desktop Users")
        Description = "Department managers with enhanced access"
    }
}

# Protected groups that should not be automatically modified
$ProtectedGroups = @(
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins"
)

# Sync results tracking
$SyncResults = @{
    GeneratedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    Computer = $env:COMPUTERNAME
    Mode = ""
    Summary = @{
        UsersProcessed = 0
        GroupsAdded = 0
        GroupsRemoved = 0
        Skipped = 0
        Errors = 0
    }
    Changes = @()
    Errors = @()
}

function Get-CurrentGroupMemberships {
    param([string]$Username)
    
    $memberships = @()
    
    try {
        $groups = Get-LocalGroup -ErrorAction SilentlyContinue
        
        foreach ($group in $groups) {
            try {
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                if ($members.Name -like "*\$Username" -or $members.Name -eq $Username) {
                    $memberships += $group.Name
                }
            }
            catch {
                # Skip groups that can't be enumerated
            }
        }
    }
    catch {
        Write-Warning "Could not enumerate groups: $_"
    }
    
    return $memberships
}

function Sync-SingleUser {
    param(
        [string]$Username,
        [string[]]$DesiredGroups,
        [bool]$RemoveFromOthers
    )
    
    $userChanges = @{
        Username = $Username
        Added = @()
        Removed = @()
        Skipped = @()
        Errors = @()
    }
    
    # Verify user exists
    try {
        $user = Get-LocalUser -Name $Username -ErrorAction Stop
    }
    catch {
        $userChanges.Errors += "User not found: $Username"
        $SyncResults.Errors += "User not found: $Username"
        $SyncResults.Summary.Errors++
        return $userChanges
    }
    
    # Get current memberships
    $currentGroups = Get-CurrentGroupMemberships -Username $Username
    
    Write-Host "  Current groups: $($currentGroups -join ', ')" -ForegroundColor Gray
    Write-Host "  Desired groups: $($DesiredGroups -join ', ')" -ForegroundColor Gray
    
    # Groups to add
    $groupsToAdd = $DesiredGroups | Where-Object { $_ -notin $currentGroups }
    
    # Groups to remove (if RemoveFromOthers is enabled)
    $groupsToRemove = @()
    if ($RemoveFromOthers) {
        $groupsToRemove = $currentGroups | Where-Object { 
            $_ -notin $DesiredGroups -and $_ -notin $ProtectedGroups
        }
    }
    
    # Add to new groups
    foreach ($group in $groupsToAdd) {
        try {
            # Check if group exists
            $groupObj = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
            
            if (-not $groupObj) {
                Write-Host "    [!] Group '$group' does not exist, skipping" -ForegroundColor Yellow
                $userChanges.Skipped += "$group (does not exist)"
                $SyncResults.Summary.Skipped++
                continue
            }
            
            if ($PSCmdlet.ShouldProcess("$Username -> $group", "Add to group")) {
                Add-LocalGroupMember -Group $group -Member $Username -ErrorAction Stop
                Write-Host "    [+] Added to: $group" -ForegroundColor Green
                $userChanges.Added += $group
                $SyncResults.Summary.GroupsAdded++
            }
            else {
                Write-Host "    [WHATIF] Would add to: $group" -ForegroundColor Cyan
                $userChanges.Added += "$group (whatif)"
            }
        }
        catch {
            if ($_.Exception.Message -like "*already a member*") {
                $userChanges.Skipped += "$group (already member)"
            }
            else {
                Write-Host "    [-] Failed to add to $group`: $($_.Exception.Message)" -ForegroundColor Red
                $userChanges.Errors += "Add to $group`: $($_.Exception.Message)"
                $SyncResults.Summary.Errors++
            }
        }
    }
    
    # Remove from groups
    foreach ($group in $groupsToRemove) {
        try {
            if ($PSCmdlet.ShouldProcess("$Username <- $group", "Remove from group")) {
                Remove-LocalGroupMember -Group $group -Member $Username -ErrorAction Stop
                Write-Host "    [-] Removed from: $group" -ForegroundColor Yellow
                $userChanges.Removed += $group
                $SyncResults.Summary.GroupsRemoved++
            }
            else {
                Write-Host "    [WHATIF] Would remove from: $group" -ForegroundColor Cyan
                $userChanges.Removed += "$group (whatif)"
            }
        }
        catch {
            Write-Host "    [!] Failed to remove from $group`: $($_.Exception.Message)" -ForegroundColor Red
            $userChanges.Errors += "Remove from $group`: $($_.Exception.Message)"
            $SyncResults.Summary.Errors++
        }
    }
    
    $SyncResults.Summary.UsersProcessed++
    return $userChanges
}

function Import-GroupAssignments {
    param([string]$FilePath)
    
    $assignments = @()
    
    if (-not (Test-Path $FilePath)) {
        throw "Source file not found: $FilePath"
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    try {
        if ($extension -eq ".json") {
            $data = Get-Content $FilePath -Raw | ConvertFrom-Json
            
            if ($data -is [array]) {
                $assignments = $data
            }
            elseif ($data.assignments) {
                $assignments = $data.assignments
            }
        }
        elseif ($extension -eq ".csv") {
            $data = Import-Csv $FilePath
            
            foreach ($row in $data) {
                $assignment = @{
                    Username = $row.Username
                    Groups = ($row.Groups -split ',').Trim()
                }
                
                if ($row.Template) {
                    $assignment.Template = $row.Template
                }
                
                $assignments += $assignment
            }
        }
        else {
            throw "Unsupported file format. Use .json or .csv"
        }
    }
    catch {
        throw "Failed to parse source file: $_"
    }
    
    return $assignments
}

# Main execution
Write-Host "`n[IdentityOps] Group Membership Synchronization" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor DarkGray

# Determine mode and process
if ($PSCmdlet.ParameterSetName -eq "File" -and $SourceFile) {
    $SyncResults.Mode = "FileImport"
    Write-Host "Mode: File Import from $SourceFile" -ForegroundColor Gray
    
    try {
        $assignments = Import-GroupAssignments -FilePath $SourceFile
        Write-Host "Loaded $($assignments.Count) user assignments" -ForegroundColor Gray
        Write-Host ""
        
        foreach ($assignment in $assignments) {
            $username = $assignment.Username
            $groups = @()
            
            if ($assignment.Template -and $RoleTemplates.ContainsKey($assignment.Template)) {
                $groups = $RoleTemplates[$assignment.Template].Groups
            }
            elseif ($assignment.Groups) {
                $groups = $assignment.Groups
            }
            
            Write-Host "`nProcessing: $username" -ForegroundColor Yellow
            $changes = Sync-SingleUser -Username $username -DesiredGroups $groups -RemoveFromOthers $RemoveExisting.IsPresent
            $SyncResults.Changes += $changes
        }
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        $SyncResults.Errors += $_.Exception.Message
        $SyncResults.Summary.Errors++
    }
}
elseif ($Username) {
    Write-Host "Mode: Single User ($Username)" -ForegroundColor Gray
    
    $targetGroups = @()
    
    if ($Template -and $RoleTemplates.ContainsKey($Template)) {
        $SyncResults.Mode = "Template:$Template"
        $targetGroups = $RoleTemplates[$Template].Groups
        Write-Host "Template: $Template - $($RoleTemplates[$Template].Description)" -ForegroundColor Gray
    }
    elseif ($Groups) {
        $SyncResults.Mode = "ManualGroups"
        $targetGroups = $Groups
    }
    else {
        Write-Host "[ERROR] Either -Template or -Groups must be specified" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "Processing: $Username" -ForegroundColor Yellow
    $changes = Sync-SingleUser -Username $Username -DesiredGroups $targetGroups -RemoveFromOthers $RemoveExisting.IsPresent
    $SyncResults.Changes += $changes
}
else {
    Write-Host "[ERROR] Either -SourceFile, or -Username with -Template/-Groups must be specified" -ForegroundColor Red
    
    Write-Host "`nAvailable templates:" -ForegroundColor Yellow
    $RoleTemplates.GetEnumerator() | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value.Description)" -ForegroundColor Gray
        Write-Host "    Groups: $($_.Value.Groups -join ', ')" -ForegroundColor DarkGray
    }
    
    exit 1
}

# Display summary
Write-Host "`n[Summary]" -ForegroundColor Cyan
Write-Host "-" * 30 -ForegroundColor DarkGray
Write-Host "Users Processed: $($SyncResults.Summary.UsersProcessed)" -ForegroundColor White
Write-Host "Groups Added: $($SyncResults.Summary.GroupsAdded)" -ForegroundColor Green
Write-Host "Groups Removed: $($SyncResults.Summary.GroupsRemoved)" -ForegroundColor Yellow
Write-Host "Skipped: $($SyncResults.Summary.Skipped)" -ForegroundColor Gray
Write-Host "Errors: $($SyncResults.Summary.Errors)" -ForegroundColor $(if ($SyncResults.Summary.Errors -gt 0) { "Red" } else { "Gray" })

# Export results
$SyncResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n[+] Sync report exported to: $OutputPath" -ForegroundColor Green

Write-Host "`n[IdentityOps] Synchronization complete.`n" -ForegroundColor Cyan
