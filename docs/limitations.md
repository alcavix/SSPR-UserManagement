# Known Limitations and Considerations

This document outlines important limitations and considerations for the SSPR Service Account Manager.

## 📚 Table of Contents
- [⚙️ Functional Limitations](#️-functional-limitations)
- [🔒 Security Considerations](#-security-considerations)
- [💻 Technical Limitations](#-technical-limitations)
- [🎯 Environment Considerations](#-environment-considerations)
- [📈 Performance Considerations](#-performance-considerations)
- [🚀 Future Enhancements](#-future-enhancements)

## ⚙️ Functional Limitations

### Single Domain Support
**Limitation:** Operates within a single Active Directory domain context.

**Impact:** Cannot manage service accounts across multiple domains in a forest.

**Workaround:** Run the script separately in each domain.

### Interactive Console Requirement
**Limitation:** Requires an interactive PowerShell console session.

**Impact:** Cannot be automated or run unattended.

**Note:** This is intentional for security - prevents accidental automated execution.

### No Bulk Operations
**Limitation:** All operations performed on individual service accounts.

**Impact:** Creating multiple accounts requires running the script multiple times.

### Limited OU Discovery
**Limitation:** No automatic OU browsing interface.

**Impact:** Users must know exact DN paths for OUs and containers.

## 🔒 Security Considerations

### Sensitive Group List Maintenance
**Limitation:** Sensitive groups list is hardcoded.

**Impact:** Custom privileged groups may not be automatically protected.

**Mitigation:** Use custom deny group functionality for environment-specific groups.

### Permission Inheritance Complexity
**Limitation:** Doesn't handle complex inheritance scenarios or conflicting ACLs.

**Best Practice:** Test thoroughly in environments with complex existing ACL structures.

### No Permission Rollback
**Limitation:** Doesn't maintain backups of original ACL states.

**Impact:** Cannot automatically rollback permission changes if issues occur.

**Mitigation:** Document original ACL states before making changes.

## 💻 Technical Limitations

### PowerShell Version Dependency
**Limitation:** Requires PowerShell 5.1 or later with specific modules.

**Impact:** Won't work on older Windows systems with PowerShell 2.0/3.0/4.0.

### Error Handling Granularity
**Limitation:** Some operations have broad error handling.

**Impact:** Generic error messages may not pinpoint exact problems.

### No Configuration File Support
**Limitation:** All configuration embedded in the script file.

**Impact:** Customizing default values requires editing the script.

**Workaround:** Maintain separate configuration files or use environment variables.

## 🎯 Environment Considerations

### Domain Controller Permissions
**Requirement:** ACL modifications require appropriate permissions on domain controllers.

**Testing:** Verify permission requirements in your specific AD environment.

### Group Policy Conflicts
**Consideration:** Existing Group Policy settings may conflict with script operations.

**Mitigation:** Review relevant GPOs before implementing SSPR service accounts.

### Compliance Requirements
**Consideration:** Some environments have specific requirements for service account management.

**Areas to Review:**
- Service account naming conventions
- Password complexity requirements
- Audit trail requirements

## 📈 Performance Considerations

### Large Environment Impact
**Limitation:** Performance may degrade in very large Active Directory environments.

**Optimization:** Run the script from domain controllers or well-connected systems.

### Replication Delays
**Consideration:** ACL changes may not immediately replicate across all domain controllers.

**Best Practice:** Allow time for replication after permission changes.

## 🚀 Future Enhancements

### Configuration Management
- External configuration file support
- Environment-specific settings

### Automation Support
- Parameter-based non-interactive mode
- CI/CD pipeline compatibility

### User Experience
- GUI interface option
- OU browsing and selection
- Bulk operations support

### Integration
- SSPR platform integration modules
- Azure AD hybrid scenarios

---

_Made with ❤️ by Tomer Alcavi_