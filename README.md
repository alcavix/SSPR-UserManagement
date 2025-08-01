# SSPR Service Account Manager

> A comprehensive PowerShell tool for creating, managing, and testing Active Directory service accounts specifically designed for Self-Service Password Reset (SSPR) systems.

[![Open Source](https://img.shields.io/badge/Open%20Source-GitHub-black?style=flat&logo=github)](https://github.com/alcavi434/SSPR-UserManagement)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE.svg?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE.svg?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![GitHub release](https://img.shields.io/github/release/alcavi434/SSPR-UserManagement.svg)](https://github.com/alcavi434/SSPR-UserManagement/releases/latest)


## 📚 Table of Contents
- [🎯 Features](#-features)
- [🛠 Requirements](#-requirements)
- [🚀 Quick Start](#-quick-start)
- [📋 Main Menu](#-main-menu)
- [💡 Example Usage](#-example-usage)
- [📁 Project Structure](#-project-structure)
- [🔒 Security](#-security)
- [📄 License](#-license)
- [💬 Feedback](#-feedback)

## 🎯 Features

- **Secure Service Account Creation** - Generate service accounts with 24+ character randomized passwords
- **Permission-Based Access Control** - Configure granular password reset permissions
- **Automatic Security Protection** - Built-in protection for sensitive groups (Domain Admins, Enterprise Admins, etc.)
- **Permission Testing & Validation** - Test and validate password reset permissions
- **Flexible Delegation Targets** - Support for OUs, Containers, and Domain Root delegation
- **Interactive Menu Interface** - User-friendly console interface with clear prompts
- **Comprehensive Logging** - Full audit trail with detailed operation logging

## 🛠 Requirements

- **PowerShell 5.1** or later
- **Active Directory PowerShell Module**
- **Administrative Privileges** (Run as Administrator)
- **Domain-Joined Environment**

## 🚀 Quick Start

1. **Launch PowerShell as Administrator**
2. **Navigate to script directory**
3. **Run the script:**

```powershell
.\SSPR-UserManagement.ps1
```

## 📋 Main Menu

📸 *Screenshot placeholder - Main menu interface*

<img src="demo/main-interface.png" alt="SSPR Service Account Manager Menu" width="100%">

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

## 💡 Example Usage

```powershell
# Creating a new SSPR service account
PS> .\SSPR-UserManagement.ps1

Select option (1-6): 1

Enter service account name: svc-sspr-test
Enter display name: SSPR Test Service Account  
Enter description: Service account for SSPR testing

[SUCCESS] Service account 'svc-sspr-test' created successfully
[SUCCESS] Password reset permissions configured with sensitive group protection

**************************************************
IMPORTANT: Save this password securely!
Password: A1b2C3d4E5f6G7h8I9j0K1l2
**************************************************
```

## 📁 Project Structure

```
SSPR-UserManagement/
├── SSPR-UserManagement.ps1    # Main script file
├── README.md                  # This file
└── docs/                      # Documentation
    ├── configuration.md       # Menu options and configuration guide
    ├── examples.md           # Usage examples and workflows
    └── limitations.md        # Known limitations and considerations
```

## 🔒 Security

**Protected Groups:** The script automatically protects sensitive groups from SSPR password reset access:
- Domain Admins, Enterprise Admins, Schema Admins
- Administrators, Account Operators
- And 15+ other privileged groups

**Logging:** All operations are logged to `%TEMP%\SSPR-ServiceAccount-Manager.log`

⚠️ **Important:** Always test in non-production environments first. Review security implications before granting password reset permissions.

## 🏷️ GitHub Topics

`active-directory` `sspr` `self-service-password-reset` `powershell` `service-account` `password-reset` `acl-management` `domain-admin` `enterprise-admin` `security-groups` `delegation` `admin-tools` `windows-server`

---

⚠️ **Disclaimer:** Use responsibly and test thoroughly before production deployment.  
The author is not responsible for any issues caused by improper use.

---
## Support & Issues

| Type | Where to Go | Description |
|------|-------------|-------------|
| **Bug Reports** | [GitHub Issues (Bug)](https://github.com/alcavi434/SSPR-UserManagement/issues/new?template=bug_report.yml) | Report crashes, errors, or unexpected behavior |
| **Feature Requests** | [GitHub Issues (Feature)](https://github.com/alcavi434/SSPR-UserManagement/issues/new?template=feature_request.yml) | Suggest new features or improvements |
| **General Discussion** | [GitHub Discussions](https://github.com/alcavi434/SSPR-UserManagement/discussions) | Ask questions, share tips, get help |

---

<div align="center">

**⭐ If this project helps you, please consider giving it a star! ⭐**

Made with ❤️ by the open-source community

[![GitHub stars](https://img.shields.io/github/stars/alcavi434/SSPR-UserManagement.svg?style=social&label=Star)](https://github.com/alcavi434/SSPR-UserManagement)
[![GitHub forks](https://img.shields.io/github/forks/alcavi434/SSPR-UserManagement.svg?style=social&label=Fork)](https://github.com/alcavi434/SSPR-UserManagement/fork)

</div>

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

This script was created with care and attention by **Tomer Alcavi**.

If you find it useful or inspiring, you're welcome to explore and learn from it —  
but please avoid re-publishing or presenting this work (in full or in part) under a different name or without proper credit.
Keeping attribution clear helps support open, respectful collaboration. Thank you!

If you have ideas for improvements or enhancements, I’d love to hear them!  
Open collaboration and respectful feedback are always welcome.

_Made with ❤️ by Tomer Alcavi_