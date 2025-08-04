#######################################################################################
#  Project:      SSPR-UserManagement
#  Version:      1.2.0
#  Author:       Tomer Alcavi
#  GitHub:       https://github.com/alcavix
#  Project Link: https://github.com/alcavix/SSPR-UserManagement
#  License:      MIT
#
#  If you find this project useful, drop a star or fork!
#  Questions or ideas? Open an issue on the project’s GitHub page!
#  Please keep this little credit line. It means a lot for the open-source spirit :)
#  Grateful for the open-source community and spirit that inspires projects like this.
#######################################################################################

#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.LINK
    https://github.com/alcavix/SSPR-UserManagement

.SYNOPSIS
    Active Directory SSPR Service Account Management Tool

.DESCRIPTION
    Comprehensive PowerShell script for creating, managing, and testing Active Directory 
    service accounts specifically designed for Self-Service Password Reset (SSPR) systems.
    
    Features:
    - Secure service account creation with randomized passwords
    - Permission-based password reset access control with ACL management
    - Automatic sensitive group protection (Domain Admins, Enterprise Admins, etc.)
    - Custom group inclusion/exclusion for password reset permissions
    - Post-creation permission editing capabilities
    - Permission validation and testing with expected behavior analysis
    - Administrative privilege enforcement
    - Audit trail and logging
    - Flexible delegation target support (OU, Container, Domain Root)
    - User-friendly console interface with clear prompts and feedback
    - including test analysis for expected behavior and security implications, 
      and to ensure permissions are set correctly (On your on responsibility, Tip: do it on test user accounts only)

.AUTHOR
    Tomer Alcavi

.VERSION
    1.2

.NOTES
    Requires:
    - PowerShell 5.1 or later
    - Active Directory PowerShell module
    - Administrative privileges
    - Domain-joined environment
    - Requires high administrative privileges to create and manage accounts
    - Supports OU, Container, and Domain Root delegation targets for SSPR permissions
    - be aware of security implications when granting password reset permissions, and 
      ensure proper testing and validation before applying to production environments
#>

#region Script Configuration
$Script:Config = @{
    ScriptMarker = "SSPR-ServiceAccount-Script-Created"
    MinPasswordLength = 24
    DefaultOU = "OU=Service Accounts,DC=domain,DC=com"  # Modify as needed
    LogPath = "$env:TEMP\SSPR-ServiceAccount-Manager.log"
    AllowedChars = @{
        Uppercase = "ABCDEFGHIJKMNPRSTUVWXYZ"
        Lowercase = "abcdefghijkmnprstuvwxyz"
        Numbers = "123456789"
        Symbols = "!#$%&"
    }
    # ADDED: Sensitive groups that SSPR accounts must NEVER have password reset permissions for
SensitiveGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Cert Publishers",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Protected Users",
    "Enterprise Key Admins",
    "Key Admins",
    "Read-only Domain Controllers",
    "Denied RODC Password Replication Group",
    "Cryptographic Operators",
    "Incoming Forest Trust Builders",
    "RAS and IAS Servers"
)    # ADDED: Default delegation target for SSPR permission management
    # Supports: OUs (OU=Users,DC=domain,DC=com), Containers (CN=Users,DC=domain,DC=com), Domain Root (DC=domain,DC=com)
    DelegationOU = "OU=Users,DC=domain,DC=com"  # Modify as needed
}
#endregion

#region Logging Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        [switch]$Silent
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $writeHostEntry = "[$Level] $Message"
    # Console output with colors
    if (-not $Silent) {
        switch ($Level) {
            "SUCCESS" { Write-Host $writeHostEntry -ForegroundColor Green }
            "WARN"    { Write-Host $writeHostEntry -ForegroundColor Yellow }
            "ERROR"   { Write-Host $writeHostEntry -ForegroundColor Red }
            default   { Write-Host $writeHostEntry -ForegroundColor White }
        }
    }
    
    # File logging
    try {
        Add-Content -Path $Script:Config.LogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silent fail for logging issues
    }
}

function Write-Section {
    param([string]$Title)
    
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}
#endregion

#region Validation Functions
function Test-Prerequisites {
    Write-Section "Checking Prerequisites"
    
    $issues = @()
    
    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $issues += "Script must be run as Administrator"
    }
    
    # Check Active Directory module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "Active Directory module loaded successfully" "SUCCESS"
    }
    catch {
        $issues += "Active Directory PowerShell module not available"
    }
    
    # Test domain connectivity
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Log "Connected to domain: $($domain.DNSRoot)" "SUCCESS"
    }
    catch {
        $issues += "Unable to connect to Active Directory domain"
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "Prerequisites check failed:" "ERROR"
        $issues | ForEach-Object { Write-Log "  - $_" "ERROR" }
        return $false
    }
    
    Write-Log "All prerequisites met" "SUCCESS"
    return $true
}

function Test-UserExists {
    param([string]$SamAccountName)
    
    try {
        $user = Get-ADUser -Identity $SamAccountName -ErrorAction Stop
        return $user
    }
    catch {
        return $null
    }
}

function Test-ScriptCreatedUser {
    param([string]$SamAccountName)
    
    try {
        $user = Get-ADUser -Identity $SamAccountName -Properties Description -ErrorAction Stop
        return $user.Description -like "*$($Script:Config.ScriptMarker)*"
    }
    catch {
        return $false
    }
}

function Test-DelegationTarget {
    param([string]$TargetDN)
    
    # ADDED: Flexible validation for different AD object types (OU, CN, domain root)
    if ([string]::IsNullOrWhiteSpace($TargetDN)) {
        return $false
    }
    
    try {
        # Try different object types based on DN structure
        if ($TargetDN -like "OU=*") {
            # Organizational Unit
            Get-ADOrganizationalUnit -Identity $TargetDN -ErrorAction Stop | Out-Null
            Write-Log "Validated delegation target as Organizational Unit: $TargetDN" "INFO"
            return $true
        }
        elseif ($TargetDN -like "CN=*" -and $TargetDN -notlike "CN=*,CN=*") {
            # Top-level container (like CN=Users)
            Get-ADObject -Identity $TargetDN -ErrorAction Stop | Out-Null
            Write-Log "Validated delegation target as Container: $TargetDN" "INFO"
            return $true
        }
        elseif ($TargetDN -like "DC=*" -and $TargetDN -notlike "*,OU=*" -and $TargetDN -notlike "*,CN=*") {
            # Domain root (only DCs in the path)
            Get-ADDomain -Identity $TargetDN -ErrorAction Stop | Out-Null
            Write-Log "Validated delegation target as Domain Root: $TargetDN" "INFO"
            return $true
        }
        else {
            # Generic AD object validation
            Get-ADObject -Identity $TargetDN -ErrorAction Stop | Out-Null
            Write-Log "Validated delegation target as AD Object: $TargetDN" "INFO"
            return $true
        }
    }
    catch {
        Write-Log "Invalid delegation target '$TargetDN': $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Permission Management Functions
# ADDED: Functions for managing password reset permissions with sensitive group protection

function Get-SensitiveGroupDNs {
    # ADDED: Retrieve distinguished names of sensitive groups to protect from SSPR access
    $sensitiveGroupDNs = @()
    
    foreach ($groupName in $Script:Config.SensitiveGroups) {
        try {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
            if ($group) {
                $sensitiveGroupDNs += $group.DistinguishedName
                Write-Log "Found sensitive group: $groupName" "INFO"
            }
        }
        catch {
            Write-Log "Warning: Could not find sensitive group '$groupName'" "WARN"
        }
    }
    
    return $sensitiveGroupDNs
}

function Set-PasswordResetPermissions {
    param(
        [string]$ServiceAccountDN,
        [string]$TargetOU,
        [string[]]$AllowedGroupDNs = @(),
        [string[]]$DeniedGroupDNs = @()
    )
    
    # ADDED: Configure password reset permissions for SSPR service account with group-level granular control
    try {
        # Import required module for ACL operations
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Get the service account's SID
        $serviceAccount = Get-ADUser -Identity $ServiceAccountDN
        $serviceAccountSID = $serviceAccount.SID
          Write-Log "Configuring password reset permissions for $($serviceAccount.SamAccountName)" "INFO"
        Write-Log "Target delegation object: $TargetOU" "INFO"
        
        # Set permissions on the target for general password reset capability
        $targetACL = Get-ACL -Path "AD:\$TargetOU"
        
        # Grant "Reset Password" permission on User objects in the OU
        $resetPasswordGUID = [GUID]"00299570-246d-11d0-a768-00aa006e0529"  # Reset Password extended right
        $userObjectGUID = [GUID]"bf967aba-0de6-11d0-a285-00aa003049e2"    # User object type
        
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $serviceAccountSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $resetPasswordGUID,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
            $userObjectGUID
        )
          $targetACL.SetAccessRule($ace)
        Set-ACL -Path "AD:\$TargetOU" -AclObject $targetACL
        Write-Log "Granted password reset permissions on delegation target: $TargetOU" "SUCCESS"
        
        # Apply explicit DENY permissions for sensitive groups
        $sensitiveGroupDNs = Get-SensitiveGroupDNs
        foreach ($groupDN in $sensitiveGroupDNs) {
            try {
                $groupACL = Get-ACL -Path "AD:\$groupDN"
                
                # Create DENY ACE for password reset on this group's members
                $denyAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $serviceAccountSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Deny,
                    $resetPasswordGUID,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                )
                
                $groupACL.SetAccessRule($denyAce)
                Set-ACL -Path "AD:\$groupDN" -AclObject $groupACL
                
                $groupName = (Get-ADGroup -Identity $groupDN).Name
                Write-Log "Applied DENY password reset permission for sensitive group: $groupName" "SUCCESS"
            }
            catch {
                Write-Log "Failed to set DENY permission for group $groupDN : $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Apply additional DENY permissions for custom denied groups
        foreach ($groupDN in $DeniedGroupDNs) {
            try {
                $groupACL = Get-ACL -Path "AD:\$groupDN"
                
                $denyAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $serviceAccountSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Deny,
                    $resetPasswordGUID,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                )
                
                $groupACL.SetAccessRule($denyAce)
                Set-ACL -Path "AD:\$groupDN" -AclObject $groupACL
                
                $groupName = (Get-ADGroup -Identity $groupDN).Name
                Write-Log "Applied custom DENY password reset permission for group: $groupName" "SUCCESS"
            }
            catch {
                Write-Log "Failed to set custom DENY permission for group $groupDN : $($_.Exception.Message)" "ERROR"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to configure password reset permissions: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-PasswordResetPermissions {
    param(
        [string]$ServiceAccountName,
        [string]$TestUserName
    )
    
    # ADDED: Test if service account can reset password for a specific user, respecting group restrictions
    try {
        $serviceAccount = Get-ADUser -Identity $ServiceAccountName -ErrorAction Stop
        $testUser = Get-ADUser -Identity $TestUserName -Properties MemberOf -ErrorAction Stop
        
        Write-Log "Testing password reset permissions for $ServiceAccountName -> $TestUserName" "INFO"
        
        # Check if test user is member of any sensitive groups
        $isMemberOfSensitiveGroup = $false
        $sensitiveGroupDNs = Get-SensitiveGroupDNs
        
        foreach ($membershipDN in $testUser.MemberOf) {
            if ($sensitiveGroupDNs -contains $membershipDN) {
                $groupName = (Get-ADGroup -Identity $membershipDN).Name
                Write-Log "Test user is member of sensitive group: $groupName" "WARN"
                $isMemberOfSensitiveGroup = $true
            }
        }
        
        if ($isMemberOfSensitiveGroup) {
            Write-Log "Permission test result: SHOULD BE DENIED (user is member of sensitive group)" "INFO"
            return @{
                ShouldBeAllowed = $false
                Reason = "User is member of sensitive group"
                TestUser = $TestUserName
                ServiceAccount = $ServiceAccountName
            }
        }
        else {
            Write-Log "Permission test result: SHOULD BE ALLOWED (user is not member of sensitive groups)" "INFO"
            return @{
                ShouldBeAllowed = $true
                Reason = "User is not member of sensitive groups"
                TestUser = $TestUserName
                ServiceAccount = $ServiceAccountName
            }
        }
    }
    catch {
        Write-Log "Failed to test permissions: $($_.Exception.Message)" "ERROR"
        return $null
    }
}
#endregion

#region Password Generation
function New-SecurePassword {
    param([int]$Length = $Script:Config.MinPasswordLength)
    
    $chars = $Script:Config.AllowedChars
    $allChars = $chars.Uppercase + $chars.Lowercase + $chars.Numbers + $chars.Symbols
    
    # Ensure at least one character from each category
    $password = @()
    $password += Get-Random -InputObject $chars.Uppercase.ToCharArray()
    $password += Get-Random -InputObject $chars.Lowercase.ToCharArray()
    $password += Get-Random -InputObject $chars.Numbers.ToCharArray()
    $password += Get-Random -InputObject $chars.Symbols.ToCharArray()
    
    # Fill remaining length with random characters
    for ($i = 4; $i -lt $Length; $i++) {
        $password += Get-Random -InputObject $allChars.ToCharArray()
    }
    
    # Shuffle the password array
    $shuffled = $password | Sort-Object { Get-Random }
    return -join $shuffled
}
#endregion

#region Service Account Management
function New-SSPRUser {
    Write-Section "Create New SSPR Service Account"
    
    # Get user input
    do {
        $samAccountName = Read-Host "Enter service account name (e.g., svc-sspr-prod)"
        if ([string]::IsNullOrWhiteSpace($samAccountName)) {
            Write-Log "Service account name cannot be empty" "ERROR"
            continue
        }
        
        if ($samAccountName.Length -lt 3) {
            Write-Log "Service account name must be at least 3 characters" "ERROR"
            continue
        }
        
        # Check if user already exists
        if (Test-UserExists -SamAccountName $samAccountName) {
            Write-Log "User '$samAccountName' already exists" "ERROR"
            continue
        }
        
        break
    } while ($true)
    
    $displayName = Read-Host "Enter display name (e.g., SSPR Service Account - Production)"
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        $displayName = "SSPR Service Account - $samAccountName"
    }
    
    $description = Read-Host "Enter description"
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = "Service account for Self-Service Password Reset system"
    }
    
    # Add script marker to description
    $description += " | $($Script:Config.ScriptMarker) | Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
      # Get target OU/Container/Domain
    $targetOU = Read-Host "Enter target OU path (press Enter for default: $($Script:Config.DefaultOU))"
    if ([string]::IsNullOrWhiteSpace($targetOU)) {
        $targetOU = $Script:Config.DefaultOU
    }
      # Validate OU exists
    if (-not (Test-DelegationTarget -TargetDN $targetOU)) {
        Write-Log "Target OU '$targetOU' not found or inaccessible" "ERROR"
        return
    }
    
    # Generate secure password
    $password = New-SecurePassword
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    
    # Confirm creation
    Write-Host "`nAccount Details:" -ForegroundColor Yellow
    Write-Host "  Name: $samAccountName" -ForegroundColor White
    Write-Host "  Display Name: $displayName" -ForegroundColor White
    Write-Host "  Description: $description" -ForegroundColor White
    Write-Host "  Target OU: $targetOU" -ForegroundColor White
    Write-Host "  Password Length: $($password.Length) characters" -ForegroundColor White
    
    $confirm = Read-Host "`nCreate this service account? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Log "Account creation cancelled by user" "WARN"
        return
    }
    
    # Create the user account
    try {
        $userParams = @{
            SamAccountName = $samAccountName
            Name = $samAccountName
            DisplayName = $displayName
            Description = $description
            Path = $targetOU
            AccountPassword = $securePassword
            Enabled = $true
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            UserPrincipalName = "$samAccountName@$((Get-ADDomain).DNSRoot)"
        }
          New-ADUser @userParams -ErrorAction Stop
        Write-Log "Service account '$samAccountName' created successfully" "SUCCESS"
        Write-Log "Details: Display Name: $displayName, Description: $description, Target OU: $targetOU" "INFO"
        Write-Log "The log will not store the password. Please make sure to save the password before proceeding." "INFO"
        
        # MODIFIED: Set up password reset permissions with sensitive group protection
        Write-Log "Configuring password reset permissions..." "INFO"        # Get delegation target for permissions
        Write-Host "`nDelegation Target Examples:" -ForegroundColor Yellow
        Write-Host "  OU: OU=Users,DC=domain,DC=com" -ForegroundColor Gray
        Write-Host "  Container: CN=Users,DC=domain,DC=com" -ForegroundColor Gray
        Write-Host "  Domain Root: DC=domain,DC=com" -ForegroundColor Gray
        
        $delegationOU = Read-Host "Enter delegation target for password reset permissions (OU/CN/Domain DN, press Enter for default: $($Script:Config.DelegationOU))"
        if ([string]::IsNullOrWhiteSpace($delegationOU)) {
            $delegationOU = $Script:Config.DelegationOU
        }
          # Validate delegation OU exists
        if (Test-DelegationTarget -TargetDN $delegationOU) {
            # Get the created user's DN for permission setup
            $createdUser = Get-ADUser -Identity $samAccountName
            $serviceAccountDN = $createdUser.DistinguishedName
            
            # Configure permissions with sensitive group protection
            if (Set-PasswordResetPermissions -ServiceAccountDN $serviceAccountDN -TargetOU $delegationOU) {
                Write-Log "Password reset permissions configured successfully with sensitive group protection" "SUCCESS"
            }
            else {
                Write-Log "Warning: Account created but permission setup failed. Manual configuration required." "WARN"
            }
        }
        else {
            Write-Log "Warning: Delegation target '$delegationOU' not found. Skipping permission setup." "WARN"
            Write-Log "Manual permission configuration will be required." "WARN"
        }
        
        # Display password securely
        Write-Host "`n" + ("*" * 50) -ForegroundColor Red
        Write-Host "IMPORTANT: Save this password securely!" -ForegroundColor Red
        Write-Host "Password: $password" -ForegroundColor Yellow
        Write-Host ("*" * 50) -ForegroundColor Red
        
        Write-Log "Account creation completed. Password displayed above." "SUCCESS"
        
    }
    catch {
        Write-Log "Failed to create service account: $($_.Exception.Message)" "ERROR"
    }
}

function Edit-SSPRUser {
    # COMPLETELY REWRITTEN: Now manages password reset permissions instead of group memberships
    Write-Section "Edit SSPR Password Reset Permissions"
    
    # Get username
    $samAccountName = Read-Host "Enter service account name to edit permissions for"
    if ([string]::IsNullOrWhiteSpace($samAccountName)) {
        Write-Log "Service account name cannot be empty" "ERROR"
        return
    }
    
    # Verify user exists and was created by this script
    if (-not (Test-UserExists -SamAccountName $samAccountName)) {
        Write-Log "User '$samAccountName' not found" "ERROR"
        return
    }
    
    if (-not (Test-ScriptCreatedUser -SamAccountName $samAccountName)) {
        Write-Log "User '$samAccountName' was not created by this script. Editing not allowed for security." "ERROR"
        return
    }
    
    Write-Log "User '$samAccountName' verified as script-created" "SUCCESS"
    
    # Get service account DN for permission operations
    $serviceAccount = Get-ADUser -Identity $samAccountName
    $serviceAccountDN = $serviceAccount.DistinguishedName
    
    # Show current sensitive group protections
    Write-Host "`nProtected Sensitive Groups (automatically protected):" -ForegroundColor Red
    foreach ($groupName in $Script:Config.SensitiveGroups) {
        Write-Host "  - $groupName" -ForegroundColor Red
    }
    
    # Permission management menu
    do {
        Write-Host "`nPassword Reset Permission Management:" -ForegroundColor Cyan
        Write-Host "1. Grant permissions on OU/Container/Domain (allow password resets)"
        Write-Host "2. Add custom group to DENY list (block password resets)"
        Write-Host "3. Remove custom group from DENY list (allow password resets)"
        Write-Host "4. Test permissions against specific user"
        Write-Host "5. Show current permission summary"
        Write-Host "6. Return to main menu"
        
        $choice = Read-Host "Select option (1-6)"
        
        switch ($choice) {
            "1" {                # Grant permissions on delegation target
                Write-Host "`nDelegation Target Examples:" -ForegroundColor Yellow
                Write-Host "  OU: OU=Users,DC=domain,DC=com" -ForegroundColor Gray
                Write-Host "  Container: CN=Users,DC=domain,DC=com" -ForegroundColor Gray
                Write-Host "  Domain Root: DC=domain,DC=com" -ForegroundColor Gray
                
                $targetOU = Read-Host "Enter delegation target DN to grant password reset permissions on (OU/CN/Domain)"
                if (-not [string]::IsNullOrWhiteSpace($targetOU)) {
                    if (Test-DelegationTarget -TargetDN $targetOU) {
                        if (Set-PasswordResetPermissions -ServiceAccountDN $serviceAccountDN -TargetOU $targetOU) {
                            Write-Log "Successfully granted password reset permissions on target: $targetOU" "SUCCESS"
                            Write-Host "NOTE: Sensitive groups are automatically protected with DENY permissions" -ForegroundColor Yellow
                        }
                        else {
                            Write-Log "Failed to grant permissions on target: $targetOU" "ERROR"
                        }
                    }
                    else {
                        Write-Log "Target not found or inaccessible: $targetOU" "ERROR"
                    }
                }
            }
            
            "2" {
                # Add custom group to deny list
                $groupName = Read-Host "Enter group name to add to DENY list"
                if (-not [string]::IsNullOrWhiteSpace($groupName)) {
                    try {
                        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                        if ($group) {
                            $groupDN = $group.DistinguishedName
                            
                            # Apply DENY permission to this group
                            if (Set-PasswordResetPermissions -ServiceAccountDN $serviceAccountDN -TargetOU "" -DeniedGroupDNs @($groupDN)) {
                                Write-Log "Successfully added '$groupName' to DENY list" "SUCCESS"
                            }
                            else {
                                Write-Log "Failed to add '$groupName' to DENY list" "ERROR"
                            }
                        }
                    }
                    catch {
                        Write-Log "Group '$groupName' not found" "ERROR"
                    }
                }
            }
            
            "3" {
                # Remove custom group from deny list (remove DENY ACE)
                $groupName = Read-Host "Enter group name to remove from DENY list"
                if (-not [string]::IsNullOrWhiteSpace($groupName)) {
                    try {
                        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                        if ($group) {
                            $groupDN = $group.DistinguishedName
                            
                            # Remove DENY ACE from group
                            $groupACL = Get-ACL -Path "AD:\$groupDN"
                            $resetPasswordGUID = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
                            
                            # Find and remove DENY ACEs for this service account
                            $acesToRemove = @()
                            foreach ($ace in $groupACL.Access) {
                                if ($ace.IdentityReference.Value -eq $serviceAccount.SID -and 
                                    $ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
                                    $ace.ObjectType -eq $resetPasswordGUID) {
                                    $acesToRemove += $ace
                                }
                            }
                            
                            foreach ($ace in $acesToRemove) {
                                $groupACL.RemoveAccessRule($ace)
                            }
                            
                            Set-ACL -Path "AD:\$groupDN" -AclObject $groupACL
                            Write-Log "Successfully removed '$groupName' from DENY list" "SUCCESS"
                        }
                    }
                    catch {
                        Write-Log "Failed to remove '$groupName' from DENY list: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
            
            "4" {
                # Test permissions against specific user
                $testUser = Read-Host "Enter username to test permissions against (Analysis Only)"
                if (-not [string]::IsNullOrWhiteSpace($testUser)) {
                    $testResult = Test-PasswordResetPermissions -ServiceAccountName $samAccountName -TestUserName $testUser
                    
                    if ($testResult) {
                        Write-Host "`nPermission Test Should be:" -ForegroundColor Yellow
                        Write-Host "  Service Account: $($testResult.ServiceAccount)" -ForegroundColor White
                        Write-Host "  Test User: $($testResult.TestUser)" -ForegroundColor White
                        
                        if ($testResult.ShouldBeAllowed) {
                            Write-Host "  Result: ALLOWED" -ForegroundColor Green
                        }
                        else {
                            Write-Host "  Result: DENIED" -ForegroundColor Red
                        }
                        
                        Write-Host "  Reason: $($testResult.Reason)" -ForegroundColor White
                    }
                    else {
                        Write-Log "Permission test failed" "ERROR"
                    }
                }
                write-Host "`nPayAttention:" -ForegroundColor Yellow
                Write-Host "This is an analysis only. No actual password reset will occur." -ForegroundColor Yellow
                write-Host "To perform an actual password reset test, Return to Main Menu and choose option 3." -ForegroundColor Yellow
            }
            
            "5" {
                # Show current permission summary
                Write-Host "`nCurrent Permission Summary:" -ForegroundColor Yellow
                Write-Host "Service Account: $samAccountName" -ForegroundColor White
                
                Write-Host "`nAutomatically Protected Groups (DENY):" -ForegroundColor Red
                #$checkmark = if ([Console]::OutputEncoding.CodePage -eq 65001) { "[√]" } else { "[√]" }

                foreach ($groupName in $Script:Config.SensitiveGroups) {
                    try {
                        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                        if ($group) {
                            Write-Host "  [√] $groupName" -ForegroundColor Red
                        }
                        else {
                            Write-Host "  [?] $groupName (not found)" -ForegroundColor Gray
                        }
                    }
                    catch {
                        Write-Host "  [?] $groupName (error checking)" -ForegroundColor Gray
                    }
                }
                
                Write-Host "`nNote: To see detailed ACL information, use AD tools or PowerShell ACL commands" -ForegroundColor Gray
            }
            
            "6" { return }
            
            default {
                Write-Log "Invalid option. Please select 1-6." "WARN"
            }
        }
    } while ($true)
}

function Test-SSPRUser {
    # MODIFIED: Enhanced to test permission restrictions and validate sensitive group protection
    Write-Section "Test SSPR Service Account Permissions"
    
    # Get service account
    $serviceAccount = Read-Host "Enter SSPR service account name"
    if ([string]::IsNullOrWhiteSpace($serviceAccount)) {
        Write-Log "Service account name cannot be empty" "ERROR"
        return
    }
    
    # Verify service account exists and was created by script
    if (-not (Test-UserExists -SamAccountName $serviceAccount)) {
        Write-Log "Service account '$serviceAccount' not found" "ERROR"
        return
    }
    
    if (-not (Test-ScriptCreatedUser -SamAccountName $serviceAccount)) {
        Write-Log "Service account '$serviceAccount' was not created by this script. Testing not allowed." "ERROR"
        return
    }
    
    # Get target user for testing
    $targetUser = Read-Host "Enter target user account to test password reset on"
    if ([string]::IsNullOrWhiteSpace($targetUser)) {
        Write-Log "Target user name cannot be empty" "ERROR"
        return
    }
    
    if (-not (Test-UserExists -SamAccountName $targetUser)) {
        Write-Log "Target user '$targetUser' not found" "ERROR"
        return
    }
    
    # ADDED: Pre-test permission analysis
    Write-Log "Analyzing permission expectations..." "INFO"
    $permissionTest = Test-PasswordResetPermissions -ServiceAccountName $serviceAccount -TestUserName $targetUser
    
    if ($permissionTest) {
        Write-Host "`nPermission Analysis:" -ForegroundColor Yellow
        Write-Host "  Target User: $($permissionTest.TestUser)" -ForegroundColor White
        
        if ($permissionTest.ShouldBeAllowed) {
            Write-Host "  Expected Result: SHOULD BE ALLOWED" -ForegroundColor Green
            Write-Host "  Reason: $($permissionTest.Reason)" -ForegroundColor White
        }
        else {
            Write-Host "  Expected Result: SHOULD BE DENIED" -ForegroundColor Red  
            Write-Host "  Reason: $($permissionTest.Reason)" -ForegroundColor White
            
            # If user is in sensitive group, recommend not proceeding with actual test
            if ($permissionTest.Reason -like "*sensitive group*") {
                Write-Host "`nSECURITY NOTICE:" -ForegroundColor Red
                Write-Host "Target user is member of a sensitive group. The password reset should be denied." -ForegroundColor Red
                Write-Host "Proceeding with the test is not recommended due to security risks or potential disruptions." -ForegroundColor Red
                Write-Host "If you choose to continue, please ensure you fully understand the consequences & risk of your actions." -ForegroundColor Red

                $proceedAnyway = Read-Host "`nProceed with actual password reset test anyway? (Y/N)"
                if ($proceedAnyway -ne 'Y' -and $proceedAnyway -ne 'y') {
                    Write-Log "Test cancelled due to sensitive group membership" "WARN"
                    return
                }
            }
        }
    }
    
    # Get service account password
    $servicePassword = Read-Host "Enter service account password" -AsSecureString
    
    # Warning about password reset
    Write-Host "`nWARNING:" -ForegroundColor Red
    Write-Host "This test will actually attempt to reset the password for user '$targetUser'" -ForegroundColor Red
    Write-Host "If successful, the user will need to be notified of their new password." -ForegroundColor Red
    
    $confirm = Read-Host "`nProceed with actual password reset test? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Log "Password reset test cancelled by user" "WARN"
        return
    }
    
    # Generate new password for target user
    $newPassword = New-SecurePassword -Length 16
    $secureNewPassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
    
    try {
        # Create credential for service account
        $serviceCredential = New-Object System.Management.Automation.PSCredential($serviceAccount, $servicePassword)
        
        # Test authentication first
        Write-Log "Testing service account authentication..." "INFO"
        
        # Attempt to read user information using service account (basic permission test)
        $testUserObj = Get-ADUser -Identity $targetUser -Credential $serviceCredential -ErrorAction Stop
        Write-Log "Service account authentication successful" "SUCCESS"
        
        # Attempt password reset
        Write-Log "Attempting password reset for '$targetUser'..." "INFO"
        Set-ADAccountPassword -Identity $targetUser -NewPassword $secureNewPassword -Reset -Credential $serviceCredential -ErrorAction Stop
        
        Write-Log "Password reset successful!" "SUCCESS"
        
        # ADDED: Validation against expected result
        if ($permissionTest -and -not $permissionTest.ShouldBeAllowed) {
            Write-Host "`n" + ("!" * 60) -ForegroundColor Red
            Write-Host "SECURITY ALERT: Password reset succeeded but was expected to be DENIED!" -ForegroundColor Red
            Write-Host "This indicates the sensitive group protection may not be working correctly!" -ForegroundColor Red
            Write-Host ("!" * 60) -ForegroundColor Red
            Write-Log "SECURITY ISSUE: Expected DENY but reset succeeded - check permissions!" "ERROR"
        }
        
        # Display results
        Write-Host "`n" + ("*" * 50) -ForegroundColor Green
        Write-Host "PASSWORD RESET TEST SUCCESSFUL" -ForegroundColor Green
        Write-Host ("*" * 50) -ForegroundColor Green
        Write-Host "Target User: $targetUser" -ForegroundColor White
        Write-Host "New Password: $newPassword" -ForegroundColor Yellow
        Write-Host "Service Account: $serviceAccount" -ForegroundColor White
        if ($permissionTest) {
            if ($permissionTest.ShouldBeAllowed) {
                Write-Host "Result vs Expected: SUCCESS (as expected)" -ForegroundColor Green
            }
            else {
                Write-Host "Result vs Expected: UNEXPECTED SUCCESS - SECURITY ISSUE!" -ForegroundColor Red
            }
        }
        Write-Host ("*" * 50) -ForegroundColor Green
        
    }
    catch {
        Write-Log "Password reset test failed: $($_.Exception.Message)" "ERROR"
        
        # ADDED: Validation against expected result for failures
        if ($permissionTest -and -not $permissionTest.ShouldBeAllowed) {
            Write-Host "`n" + ("*" * 50) -ForegroundColor Green
            Write-Host "PERMISSION RESTRICTION WORKING CORRECTLY" -ForegroundColor Green
            Write-Host ("*" * 50) -ForegroundColor Green
            Write-Host "Target User: $targetUser" -ForegroundColor White
            Write-Host "Service Account: $serviceAccount" -ForegroundColor White
            Write-Host "Result: DENIED (as expected for sensitive group member)" -ForegroundColor Green
            Write-Host "Security Status: PROTECTED" -ForegroundColor Green
            Write-Host ("*" * 50) -ForegroundColor Green
        }
        
        # Common error analysis
        if ($_.Exception.Message -like "*Access is denied*") {
            Write-Log "Service account lacks permission to reset passwords for this user" "ERROR"
            Write-Log "This may be expected behavior if user is in a protected group" "INFO"        }
        elseif ($_.Exception.Message -like "*password does not meet*") {
            Write-Log "Generated password does not meet domain password policy" "ERROR"
        }
        elseif ($_.Exception.Message -like "*authentication*") {
            Write-Log "Service account authentication failed - check password" "ERROR"
        }
    }
}

function Reset-SSPRUserToDefault {
    # ADDED: Reset SSPR service account permissions to default state
    Write-Section "Fix/Default SSPR User Permission Set"
    
    # Get service account name
    $samAccountName = Read-Host "Enter SSPR service account name to reset to default permissions"
    if ([string]::IsNullOrWhiteSpace($samAccountName)) {
        Write-Log "Service account name cannot be empty" "ERROR"
        return
    }
    
    # Verify user exists and was created by this script
    if (-not (Test-UserExists -SamAccountName $samAccountName)) {
        Write-Log "User '$samAccountName' not found" "ERROR"
        return
    }
    
    if (-not (Test-ScriptCreatedUser -SamAccountName $samAccountName)) {
        Write-Log "User '$samAccountName' was not created by this script. Reset not allowed for security." "ERROR"
        return
    }
    
    Write-Log "User '$samAccountName' verified as script-created" "SUCCESS"    # Get delegation target for default permissions
    Write-Host "`nDelegation Target Examples:" -ForegroundColor Yellow
    Write-Host "  OU: OU=Users,DC=domain,DC=com" -ForegroundColor Gray
    Write-Host "  Container: CN=Users,DC=domain,DC=com" -ForegroundColor Gray
    Write-Host "  Domain Root: DC=domain,DC=com" -ForegroundColor Gray
    
    $delegationOU = Read-Host "Enter delegation target for default password reset permissions (OU/CN/Domain DN, press Enter for default: $($Script:Config.DelegationOU))"
    if ([string]::IsNullOrWhiteSpace($delegationOU)) {
        $delegationOU = $Script:Config.DelegationOU
    }
      # Validate delegation OU exists
    if (-not (Test-DelegationTarget -TargetDN $delegationOU)) {
        Write-Log "Delegation target '$delegationOU' not found or inaccessible" "ERROR"
        return
    }
    
    # Get service account DN
    $serviceAccount = Get-ADUser -Identity $samAccountName
    $serviceAccountDN = $serviceAccount.DistinguishedName
      # Show what will be done
    Write-Host "`nDefault Permission Reset Details:" -ForegroundColor Yellow
    Write-Host "  Service Account: $samAccountName" -ForegroundColor White
    Write-Host "  Target: $delegationOU" -ForegroundColor White
    Write-Host "  Action: Grant password reset permissions for all users" -ForegroundColor White
    Write-Host "  Protection: Apply DENY permissions for sensitive groups" -ForegroundColor White
    
    Write-Host "`nSensitive Groups (will be protected with DENY):" -ForegroundColor Red
    foreach ($groupName in $Script:Config.SensitiveGroups) {
        Write-Host "  - $groupName" -ForegroundColor Red
    }
    
    $confirm = Read-Host "`nProceed with permission reset to default state? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Log "Permission reset cancelled by user" "WARN"
        return
    }
    
    try {
        Write-Log "Starting permission reset to default state..." "INFO"
        
        # Step 1: Remove existing permissions for this service account
        Write-Log "Step 1: Cleaning existing permissions..." "INFO"
        
        # Get all ACLs where this service account might have permissions
        $resetPasswordGUID = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
          # Clean delegation target permissions first
        try {
            $targetACL = Get-ACL -Path "AD:\$delegationOU"
            $acesToRemove = @()
            
            foreach ($ace in $targetACL.Access) {
                if ($ace.IdentityReference.Value -eq $serviceAccount.SID -and 
                    $ace.ObjectType -eq $resetPasswordGUID) {
                    $acesToRemove += $ace
                }
            }
            
            foreach ($ace in $acesToRemove) {
                $targetACL.RemoveAccessRule($ace)
            }
            
            if ($acesToRemove.Count -gt 0) {
                Set-ACL -Path "AD:\$delegationOU" -AclObject $targetACL
                Write-Log "Removed $($acesToRemove.Count) existing ACE(s) from delegation target: $delegationOU" "INFO"
            }
        }
        catch {
            Write-Log "Warning: Could not clean existing delegation target permissions: $($_.Exception.Message)" "WARN"
        }
        
        # Clean sensitive group permissions
        $sensitiveGroupDNs = Get-SensitiveGroupDNs
        foreach ($groupDN in $sensitiveGroupDNs) {
            try {
                $groupACL = Get-ACL -Path "AD:\$groupDN"
                $acesToRemove = @()
                
                foreach ($ace in $groupACL.Access) {
                    if ($ace.IdentityReference.Value -eq $serviceAccount.SID -and 
                        $ace.ObjectType -eq $resetPasswordGUID) {
                        $acesToRemove += $ace
                    }
                }
                
                foreach ($ace in $acesToRemove) {
                    $groupACL.RemoveAccessRule($ace)
                }
                
                if ($acesToRemove.Count -gt 0) {
                    Set-ACL -Path "AD:\$groupDN" -AclObject $groupACL
                    $groupName = (Get-ADGroup -Identity $groupDN).Name
                    Write-Log "Cleaned existing permissions from sensitive group: $groupName" "INFO"
                }
            }
            catch {
                Write-Log "Warning: Could not clean permissions from group $groupDN : $($_.Exception.Message)" "WARN"
            }
        }
        
        # Step 2: Apply default permissions
        Write-Log "Step 2: Applying default permissions..." "INFO"
        
        if (Set-PasswordResetPermissions -ServiceAccountDN $serviceAccountDN -TargetOU $delegationOU) {
            Write-Log "Default permissions applied successfully" "SUCCESS"
            
            # Display results
            Write-Host "`n" + ("*" * 60) -ForegroundColor Green
            Write-Host "PERMISSION RESET TO DEFAULT STATE COMPLETED" -ForegroundColor Green
            Write-Host ("*" * 60) -ForegroundColor Green
            Write-Host "Service Account: $samAccountName" -ForegroundColor White
            Write-Host "Target: $delegationOU" -ForegroundColor White
            Write-Host "Status: Password reset permissions granted for all users" -ForegroundColor Green
            Write-Host "Protection: All sensitive groups automatically protected" -ForegroundColor Green
            Write-Host ("*" * 60) -ForegroundColor Green
            
            Write-Log "Permission reset completed successfully" "SUCCESS"
        }
        else {
            Write-Log "Failed to apply default permissions" "ERROR"
        }
    }
    catch {
        Write-Log "Failed to reset permissions to default state: $($_.Exception.Message)" "ERROR"
    }
}
#endregion

#region Main Menu
function Show-MainMenu {
    Clear-Host

    Write-Host @"
################################################################
#               SSPR Service Account Manager                   #
#                                                              #
#       Secure Active Directory Service Account Tool           #
################################################################
"@ -ForegroundColor Cyan

    Write-Host "`nAvailable Operations:" -ForegroundColor Yellow
    Write-Host "1. Create New SSPR Service Account" -ForegroundColor White
    Write-Host "2. Edit SSPR Password Reset Permissions" -ForegroundColor White
    Write-Host "3. Test SSPR Service Account Permissions" -ForegroundColor White
    Write-Host "4. Restore Default SSPR Service Permission Set" -ForegroundColor White
    Write-Host "5. View Script Information" -ForegroundColor White
    Write-Host "6. Exit" -ForegroundColor White

    #Write-Host "`nScript Log: $($Script:Config.LogPath)" -ForegroundColor Gray
}

function Show-ScriptInfo {
    Write-Section "Script Information"
    
    Write-Host "Script Version: 1.0" -ForegroundColor White
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host "Execution Policy: $(Get-ExecutionPolicy)" -ForegroundColor White
    Write-Host "Domain: $((Get-ADDomain).DNSRoot)" -ForegroundColor White
    Write-Host "Current User: $($env:USERNAME)" -ForegroundColor White
    Write-Host "Script Marker: $($Script:Config.ScriptMarker)" -ForegroundColor White
    Write-Host "Default OU: $($Script:Config.DefaultOU)" -ForegroundColor White
    Write-Host "Default Delegation Target: $($Script:Config.DelegationOU)" -ForegroundColor White
    Write-Host "Min Password Length: $($Script:Config.MinPasswordLength)" -ForegroundColor White
    Write-Host "Log File: $($Script:Config.LogPath)" -ForegroundColor White
    
    Write-Host "`nSensitive Groups (Auto-Protected):" -ForegroundColor Red
    foreach ($group in $Script:Config.SensitiveGroups) {
        Write-Host "  - $group" -ForegroundColor Red
    }
    
    Write-Host "`nSupported Delegation Targets:" -ForegroundColor Yellow
    Write-Host "- Organizational Units: OU=Users,DC=domain,DC=com" -ForegroundColor White
    Write-Host "- Container Objects: CN=Users,DC=domain,DC=com" -ForegroundColor White
    Write-Host "- Domain Root: DC=domain,DC=com" -ForegroundColor White
    Write-Host "- Custom AD Objects: Any valid AD object DN" -ForegroundColor White
    
    Write-Host "`nSecurity Features:" -ForegroundColor Yellow
    Write-Host "- Administrative privilege enforcement" -ForegroundColor White
    Write-Host "- Script-created account tagging and validation" -ForegroundColor White
    Write-Host "- Secure password generation (24`+ characters)" -ForegroundColor White
    Write-Host "- Comprehensive input validation" -ForegroundColor White
    Write-Host "- Audit logging" -ForegroundColor White
    Write-Host "- Safe testing with confirmation prompts" -ForegroundColor White
    Write-Host "- Automatic sensitive group protection (DENY permissions)" -ForegroundColor White
    Write-Host "- Permission-based access control with ACL management" -ForegroundColor White
    Write-Host "- Pre-test permission analysis and validation" -ForegroundColor White
    
    Read-Host "`nPress Enter to continue"
}

function Start-SSPRManager {
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites not met. Exiting." "ERROR"
        Read-Host "Press Enter to exit"
        return
    }
    
    Write-Log "SSPR Service Account Manager started" "INFO"
    
    do {
        Show-MainMenu
        $choice = Read-Host "`nSelect option (1-6)"
        
        switch ($choice) {
            "1" { New-SSPRUser }  
            "2" { Edit-SSPRUser }
            "3" { Test-SSPRUser }
            "4" { Reset-SSPRUserToDefault }
            "5" { Show-ScriptInfo }
            "6" {
                Write-Log "SSPR Service Account Manager exiting" "INFO"
                Write-Host "Thank you for using the SSPR Service Account Manager!" -ForegroundColor Green
                #write-host "Created with ♥ Tomer Alcavi" -ForegroundColor Cyan
                write-host "Created by Tomer Alcavi" -ForegroundColor Cyan
                write-host "Log file: $($Script:Config.LogPath)" -ForegroundColor Gray
                return 
            }
            default {
                Write-Log "Invalid menu selection: $choice" "WARN"
                Start-Sleep -Seconds 2
            }
        }
        
        if ($choice -in @("1","2","3","4","5")) {
            Write-Host "`nOperation completed. " -NoNewline -ForegroundColor Green
            Read-Host "Press Enter to return to main menu"
        }
        
    } while ($true)
}
#endregion

# Script entry point
if ($MyInvocation.InvocationName -ne '.') {
    # Create Log of new session
    Write-Log "$("=" * 60)" -Silent
    Write-Log "SSPR Service Account Manager started" "INFO" -Silent
    Write-Log "$("=" * 30)" -Silent
    Write-Log "Date & Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm')" "INFO" -Silent
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" "INFO" -Silent
    Write-Log "Execution Policy: $(Get-ExecutionPolicy)" "INFO" -Silent
    Write-Log "Domain: $((Get-ADDomain).DNSRoot)" "INFO" -Silent
    Write-Log "User: $($env:USERNAME)" "INFO" -Silent
    Write-Log "Computer Name: $($env:COMPUTERNAME)" "INFO" -Silent
    Write-Log "OS: $($env:OS)" "INFO" -Silent
    Write-Log "Script Marker: $($Script:Config.ScriptMarker)" "INFO" -Silent
    Write-Log "$("=" * 60)" -Silent
    Start-SSPRManager
}
