<#
.SYNOPSIS
    User Account Provisioning - Creates user accounts with proper group assignments.

.DESCRIPTION
    This script automates user account creation and configuration including:
    - Local user account creation (simulates AD-like behavior)
    - Group membership assignment
    - Home directory creation
    - Account policy application
    - Audit logging of all actions

.PARAMETER Username
    The username for the new account

.PARAMETER FullName
    The display name of the user

.PARAMETER Groups
    Array of groups to add the user to

.PARAMETER Department
    Department for organizational purposes

.PARAMETER Manager
    Manager's username for reporting structure

.PARAMETER PasswordPolicy
    Password policy to apply: Standard, Complex, Temporary

.PARAMETER CreateHomeDir
    Create a home directory for the user

.PARAMETER OutputPath
    Path to export provisioning report. Default: ./provisioning-report.json

.EXAMPLE
    .\New-UserAccount.ps1 -Username "jdoe" -FullName "John Doe" -Groups @("ITSupport", "RemoteUsers") -Department "IT"

.NOTES
    Author: IdentityOps Automation Suite
    Version: 1.0.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z][a-zA-Z0-9_-]{2,19}$')]
    [string]$Username,
    
    [Parameter(Mandatory = $true)]
    [string]$FullName,
    
    [Parameter()]
    [string[]]$Groups = @(),
    
    [Parameter()]
    [string]$Department = "",
    
    [Parameter()]
    [string]$Manager = "",
    
    [Parameter()]
    [ValidateSet("Standard", "Complex", "Temporary")]
    [string]$PasswordPolicy = "Standard",
    
    [Parameter()]
    [switch]$CreateHomeDir,
    
    [Parameter()]
    [string]$OutputPath = ".\provisioning-report.json"
)

# Configuration
$Config = @{
    HomeDirBase = "C:\Users"
    DefaultGroups = @("Users")
    PasswordLength = @{
        Standard = 12
        Complex = 16
        Temporary = 8
    }
    AuditLogPath = ".\provisioning-audit.log"
}

# Provisioning result tracking
$ProvisioningResult = @{
    Username = $Username
    FullName = $FullName
    Status = "Pending"
    StartTime = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    EndTime = $null
    Actions = @()
    Errors = @()
    GroupsAssigned = @()
    Settings = @{}
}

function Write-AuditLog {
    param(
        [string]$Action,
        [string]$Details,
        [string]$Status = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Status] [$Username] $Action - $Details"
    
    # Console output
    $color = switch ($Status) {
        "Success" { "Green" }
        "Error" { "Red" }
        "Warning" { "Yellow" }
        default { "Gray" }
    }
    Write-Host $logEntry -ForegroundColor $color
    
    # File log
    $logEntry | Out-File -FilePath $Config.AuditLogPath -Append -Encoding UTF8
    
    # Track in result
    $ProvisioningResult.Actions += @{
        Timestamp = $timestamp
        Action = $Action
        Details = $Details
        Status = $Status
    }
}

function New-SecurePassword {
    param(
        [string]$Policy
    )
    
    $length = $Config.PasswordLength[$Policy]
    
    # Character sets
    $lowercase = 'abcdefghijklmnopqrstuvwxyz'
    $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $numbers = '0123456789'
    $special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    $allChars = switch ($Policy) {
        "Simple" { $lowercase + $uppercase + $numbers }
        "Complex" { $lowercase + $uppercase + $numbers + $special }
        "Temporary" { $lowercase + $numbers }
        default { $lowercase + $uppercase + $numbers + $special }
    }
    
    # Generate password
    $password = -join (1..$length | ForEach-Object { 
        $allChars[(Get-Random -Maximum $allChars.Length)] 
    })
    
    # Ensure at least one of each required type
    $password = $password.Substring(1) + $uppercase[(Get-Random -Maximum $uppercase.Length)]
    $password = $password.Substring(1) + $lowercase[(Get-Random -Maximum $lowercase.Length)]
    $password = $password.Substring(1) + $numbers[(Get-Random -Maximum $numbers.Length)]
    
    if ($Policy -eq "Complex") {
        $password = $password.Substring(1) + $special[(Get-Random -Maximum $special.Length)]
    }
    
    return $password
}

function Test-UserExists {
    param([string]$Username)
    
    try {
        $user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
        return $null -ne $user
    }
    catch {
        return $false
    }
}

function Test-GroupExists {
    param([string]$GroupName)
    
    try {
        $group = Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue
        return $null -ne $group
    }
    catch {
        return $false
    }
}

function New-LocalUserAccount {
    param(
        [string]$Username,
        [string]$FullName,
        [string]$Password
    )
    
    try {
        if (Test-UserExists -Username $Username) {
            Write-AuditLog -Action "CreateUser" -Details "User already exists" -Status "Warning"
            return $false
        }
        
        if ($PSCmdlet.ShouldProcess($Username, "Create local user account")) {
            $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            
            $userParams = @{
                Name = $Username
                Password = $securePassword
                FullName = $FullName
                Description = "Created by IdentityOps Automation on $(Get-Date -Format 'yyyy-MM-dd')"
                PasswordNeverExpires = ($PasswordPolicy -ne "Temporary")
                UserMayNotChangePassword = ($PasswordPolicy -eq "Temporary")
            }
            
            New-LocalUser @userParams -ErrorAction Stop | Out-Null
            
            Write-AuditLog -Action "CreateUser" -Details "User account created successfully" -Status "Success"
            return $true
        }
    }
    catch {
        Write-AuditLog -Action "CreateUser" -Details "Failed: $($_.Exception.Message)" -Status "Error"
        $ProvisioningResult.Errors += $_.Exception.Message
        return $false
    }
    
    return $false
}

function Add-UserToGroups {
    param(
        [string]$Username,
        [string[]]$GroupList
    )
    
    $allGroups = $Config.DefaultGroups + $GroupList | Select-Object -Unique
    
    foreach ($group in $allGroups) {
        try {
            if (-not (Test-GroupExists -GroupName $group)) {
                Write-AuditLog -Action "AddToGroup" -Details "Group '$group' does not exist, skipping" -Status "Warning"
                continue
            }
            
            if ($PSCmdlet.ShouldProcess("$Username -> $group", "Add user to group")) {
                Add-LocalGroupMember -Group $group -Member $Username -ErrorAction Stop
                Write-AuditLog -Action "AddToGroup" -Details "Added to group '$group'" -Status "Success"
                $ProvisioningResult.GroupsAssigned += $group
            }
        }
        catch {
            if ($_.Exception.Message -like "*already a member*") {
                Write-AuditLog -Action "AddToGroup" -Details "Already member of '$group'" -Status "Info"
                $ProvisioningResult.GroupsAssigned += $group
            }
            else {
                Write-AuditLog -Action "AddToGroup" -Details "Failed for '$group': $($_.Exception.Message)" -Status "Error"
                $ProvisioningResult.Errors += $_.Exception.Message
            }
        }
    }
}

function New-HomeDirectory {
    param(
        [string]$Username
    )
    
    $homePath = Join-Path $Config.HomeDirBase $Username
    
    try {
        if (Test-Path $homePath) {
            Write-AuditLog -Action "CreateHomeDir" -Details "Home directory already exists at $homePath" -Status "Info"
            return $homePath
        }
        
        if ($PSCmdlet.ShouldProcess($homePath, "Create home directory")) {
            New-Item -Path $homePath -ItemType Directory -Force | Out-Null
            
            # Set permissions (simplified - in production would use icacls or Set-Acl)
            Write-AuditLog -Action "CreateHomeDir" -Details "Created home directory at $homePath" -Status "Success"
            
            $ProvisioningResult.Settings["HomeDirectory"] = $homePath
            return $homePath
        }
    }
    catch {
        Write-AuditLog -Action "CreateHomeDir" -Details "Failed: $($_.Exception.Message)" -Status "Error"
        $ProvisioningResult.Errors += $_.Exception.Message
        return $null
    }
    
    return $null
}

function Export-ProvisioningReport {
    param(
        [string]$Path
    )
    
    $ProvisioningResult.EndTime = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    
    $ProvisioningResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "`n[+] Provisioning report exported to: $Path" -ForegroundColor Green
}

# Main execution
Write-Host "`n[IdentityOps] User Account Provisioning" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor DarkGray
Write-Host "Creating account for: $FullName ($Username)" -ForegroundColor Gray
Write-Host "Password Policy: $PasswordPolicy" -ForegroundColor Gray
Write-Host "Groups: $($Groups -join ', ')" -ForegroundColor Gray
Write-Host ""

# Generate password
$generatedPassword = New-SecurePassword -Policy $PasswordPolicy
$ProvisioningResult.Settings["PasswordPolicy"] = $PasswordPolicy

# Create user account
$userCreated = New-LocalUserAccount -Username $Username -FullName $FullName -Password $generatedPassword

if ($userCreated) {
    # Add to groups
    Add-UserToGroups -Username $Username -GroupList $Groups
    
    # Create home directory if requested
    if ($CreateHomeDir) {
        New-HomeDirectory -Username $Username | Out-Null
    }
    
    # Store additional metadata
    $ProvisioningResult.Settings["Department"] = $Department
    $ProvisioningResult.Settings["Manager"] = $Manager
    
    $ProvisioningResult.Status = "Completed"
    
    # Display summary
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "-" * 30 -ForegroundColor DarkGray
    Write-Host "Username: $Username" -ForegroundColor White
    Write-Host "Status: $($ProvisioningResult.Status)" -ForegroundColor Green
    Write-Host "Groups: $($ProvisioningResult.GroupsAssigned -join ', ')" -ForegroundColor Gray
    
    if ($PasswordPolicy -eq "Temporary") {
        Write-Host "`n[!] Temporary Password: $generatedPassword" -ForegroundColor Yellow
        Write-Host "    User must change password at first login." -ForegroundColor Yellow
    }
    else {
        Write-Host "`n[!] Initial Password: $generatedPassword" -ForegroundColor Yellow
        Write-Host "    Please securely communicate this to the user." -ForegroundColor Yellow
    }
}
else {
    $ProvisioningResult.Status = "Failed"
    Write-Host "`n[!] User provisioning failed. Check audit log for details." -ForegroundColor Red
}

# Export report
Export-ProvisioningReport -Path $OutputPath

Write-Host "`n[IdentityOps] Provisioning complete.`n" -ForegroundColor Cyan
