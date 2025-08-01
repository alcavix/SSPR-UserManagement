# Configuration and Menu Options Guide

This document explains the functionality behind each menu option and configuration settings.

## 📚 Table of Contents
- [⚙️ Script Configuration](#️-script-configuration)
- [📋 Menu Options](#-menu-options)
- [🔒 Security Features](#-security-features)
- [🎯 Delegation Targets](#-delegation-targets)

## ⚙️ Script Configuration

The script uses centralized configuration settings:

```powershell
$Script:Config = @{
    ScriptMarker = "SSPR-ServiceAccount-Script-Created"
    MinPasswordLength = 24
    DefaultOU = "OU=Service Accounts,DC=domain,DC=com"
    DelegationOU = "OU=Users,DC=domain,DC=com"
    SensitiveGroups = @("Domain Admins", "Enterprise Admins", ...)
}
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ScriptMarker` | Identifier for script-created accounts | "SSPR-ServiceAccount-Script-Created" |
| `MinPasswordLength` | Minimum password length | 24 characters |
| `DefaultOU` | Default OU for service accounts | "OU=Service Accounts,DC=domain,DC=com" |
| `DelegationOU` | Default target for permissions | "OU=Users,DC=domain,DC=com" |

## 📋 Menu Options

### 1. Create New SSPR Service Account

Creates a new Active Directory service account with secure password reset permissions.

**Process:**
- **Account Validation:** Minimum 3 characters, checks for duplicates
- **Secure Attributes:** PasswordNeverExpires, CannotChangePassword, Enabled
- **Password Generation:** 24+ characters with mixed character sets
- **Permission Setup:** Grants reset rights, protects sensitive groups

### 2. Edit SSPR Password Reset Permissions

Modify permissions for existing script-created service accounts.

**Available Actions:**
- Grant permissions on delegation targets
- Add/remove custom groups from deny list
- Test permissions against specific users
- View current permission summary

### 3. Test SSPR Service Account Permissions

Validate service account permissions work correctly.

**Process:**
- Pre-test analysis of user group memberships
- Authentication testing
- Actual password reset attempt
- Security validation and result analysis

### 4. Restore Default SSPR Permission Set

Reset service account permissions to default state.

**Process:**
- Remove existing custom permissions
- Re-apply standard password reset permissions
- Maintain sensitive group protections

### 5. View Script Information

Display comprehensive script and environment information.

## 🔒 Security Features

### Sensitive Groups Protection

The script automatically protects these groups with DENY permissions:

**Administrative Groups:**
- Domain Admins, Enterprise Admins, Schema Admins, Administrators

**Operational Groups:**
- Account Operators, Backup Operators, Server Operators, Print Operators

**Security Groups:**
- Protected Users, Enterprise Key Admins, Key Admins, Cryptographic Operators

**Infrastructure Groups:**
- DnsAdmins, Group Policy Creator Owners, RAS and IAS Servers

### Permission Model
- Uses Windows ACLs with specific GUIDs for password reset rights
- Implements explicit DENY over ALLOW for sensitive groups
- Supports inheritance for descendant objects

### Account Protection
- Script marker prevents modification of non-script accounts
- Administrative privilege enforcement
- Comprehensive input validation

## 🎯 Delegation Targets

### Organizational Units (OUs)
```
Format: OU=Users,DC=domain,DC=com
Use Case: Standard user containers
```

### Container Objects
```
Format: CN=Users,DC=domain,DC=com
Use Case: Built-in containers like CN=Users
```

### Domain Root
```
Format: DC=domain,DC=com
Use Case: Domain-wide password reset permissions
```

---

_Made with ❤️ by Tomer Alcavi_