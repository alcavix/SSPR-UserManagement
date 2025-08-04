# Usage Examples and Workflows

This document provides practical examples and typical workflows for common tasks.

## 📚 Table of Contents
- [🖥️ Main Menu](#️-main-menu)
- [🚀 Common Workflows](#-common-workflows)
- [⚠️ Error Scenarios](#️-error-scenarios)
- [💡 Best Practices](#-best-practices)

## 🖥️ Main Menu

When you launch the script, you'll see this main menu:

```
################################################################
#               SSPR Service Account Manager                   #
#                                                              #
#       Secure Active Directory Service Account Tool           #
################################################################

Available Operations:
1. Create New SSPR Service Account
2. Edit SSPR Password Reset Permissions
3. Test SSPR Service Account Permissions
4. Restore Default SSPR Service Permission Set
5. View Script Information
6. Exit

Select option (1-6):
```

## 🚀 Common Workflows

### Workflow 1: Creating a Production Service Account

```powershell
# Step 1: Launch script and select option 1
Select option (1-6): 1

# Step 2: Provide account details
Enter service account name: svc-sspr-production
Enter display name: SSPR Production Service Account
Enter description: Production service account for self-service password reset

# Step 3: Review and confirm
Create this service account? (Y/N): Y

[SUCCESS] Service account 'svc-sspr-production' created successfully
[SUCCESS] Password reset permissions configured with sensitive group protection

# Step 4: Secure the password
**************************************************
IMPORTANT: Save this password securely!
Password: K8mN2pQ7rT9uV3xZ1aB4cD6eF
**************************************************
```

### Workflow 2: Testing Service Account Permissions

```powershell
# Test with regular user
Select option (1-6): 3

Enter SSPR service account name: svc-sspr-production
Enter target user account to test: john.doe

Permission Analysis:
  Target User: john.doe
  Expected Result: SHOULD BE ALLOWED
  Reason: User is not member of sensitive groups

Enter service account password: ****************
Proceed with actual password reset test? (Y/N): Y

[SUCCESS] Password reset successful!

**************************************************
PASSWORD RESET TEST SUCCESSFUL
**************************************************
Target User: john.doe
New Password: A1b2C3d4E5f6G7h8
Result vs Expected: SUCCESS (as expected)
**************************************************
```

### Workflow 3: Testing Protection for Sensitive Groups

```powershell
# Test against a Domain Admin user
Enter target user account to test: domain.admin

Permission Analysis:
  Target User: domain.admin
  Expected Result: SHOULD BE DENIED
  Reason: User is member of sensitive group

SECURITY NOTICE:
Target user is member of a sensitive group. The password reset should be denied.

Proceed with actual password reset test anyway? (Y/N): N

[WARN] Test cancelled due to sensitive group membership
```

### Workflow 4: Adding Custom Protected Groups

```powershell
# Step 1: Select edit option
Select option (1-6): 2

Enter service account name to edit permissions for: svc-sspr-production

Password Reset Permission Management:
1. Grant permissions on OU/Container/Domain
2. Add custom group to DENY list
3. Remove custom group from DENY list
4. Test permissions against specific user
5. Show current permission summary
6. Return to main menu

# Step 2: Add custom group to deny list
Select option (1-6): 2

Enter group name to add to DENY list: IT-Staff
[SUCCESS] Successfully added 'IT-Staff' to DENY list
```

## ⚠️ Error Scenarios

### Missing Prerequisites

```powershell
[ERROR] Script must be run as Administrator
[ERROR] Active Directory PowerShell module not available
Prerequisites not met. Exiting.
```

### Invalid Input

```powershell
Enter service account name: ab
[ERROR] Service account name must be at least 3 characters

Enter service account name: existing-user
[ERROR] User 'existing-user' already exists
```

### Permission Test Failures

```powershell
[ERROR] Password reset test failed: Access is denied
[ERROR] Service account lacks permission to reset passwords for this user

************************************************************
PERMISSION RESTRICTION WORKING CORRECTLY
************************************************************
Target User: sensitive.user
Result: DENIED (as expected for sensitive group member)
Security Status: PROTECTED
************************************************************
```

## 💡 Best Practices

### Creating Service Accounts
- Use descriptive naming: `svc-sspr-[environment]`
- Provide clear descriptions
- Test immediately after creation
- Document passwords securely

### Permission Management
- Start with default permissions
- Add custom deny groups sparingly
- Test thoroughly before production use
- Document custom configurations

### Testing Workflows
- Test with regular users first
- Test with sensitive group members
- Verify expected deny behavior
- Coordinate with users for password changes

### Maintenance
- Review permissions periodically
- Monitor logs for security events
- Keep backups of working configurations

---

_Made with ❤️ by Tomer Alcavi_