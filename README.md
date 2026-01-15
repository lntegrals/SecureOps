# SecureOps Automation Suite

A comprehensive automation toolkit for system administration, security auditing, and identity management. Built with PowerShell and Python.

## 🔧 Components

### SecurOps Automation Suite
PowerShell and Python scripts for **system auditing and log analysis**.

| Component | Technology | Description |
|-----------|------------|-------------|
| Security Event Auditor | PowerShell | Parse Windows Security Event Logs for critical events |
| File Permission Scanner | PowerShell | Scan directories for permission vulnerabilities |
| Service Status Auditor | PowerShell | Monitor Windows services for issues |
| Log Parser | Python | Multi-format log parsing (syslog, JSON, CSV) |
| Anomaly Detector | Python | Statistical anomaly detection in logs |
| Log Aggregator | Python | Unified log collection from multiple sources |
| Health Monitor | Flask + React | Real-time system health dashboard |

### IdentityOps Access Automation
Scripts for **user provisioning and integration health monitoring**.

| Component | Technology | Description |
|-----------|------------|-------------|
| User Account Provisioning | PowerShell | Automated user creation with group management |
| Permission Auditor | PowerShell | Audit user/group permissions with risk assessment |
| Group Sync | PowerShell | Role-based group membership synchronization |
| Log Retriever | Python | Automated system log retrieval |
| Service Monitor | Python | Multi-service health monitoring |
| Uptime Tracker | Python | SLA compliance and incident tracking |
| Integration Dashboard | Flask + React | Service health visualization |

---

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ or PowerShell 7+
- Python 3.9+
- Node.js 18+ (for dashboards)

### PowerShell Scripts

```powershell
# Security Event Audit
.\securops-automation\powershell\Audit-SecurityEvents.ps1 -Hours 24 -OutputPath ".\security-report.json"

# File Permission Scan
.\securops-automation\powershell\Scan-FilePermissions.ps1 -Path "C:\Shares" -Depth 3

# Service Status Audit
.\securops-automation\powershell\Audit-Services.ps1 -CriticalOnly

# User Provisioning
.\identityops\powershell\New-UserAccount.ps1 -Username "jdoe" -FullName "John Doe" -Groups @("IT", "RemoteUsers")

# Permission Audit
.\identityops\powershell\Audit-Permissions.ps1 -Scope All -PrivilegedOnly

# Group Synchronization
.\identityops\powershell\Sync-UserGroups.ps1 -Username "jdoe" -Template "IT"
```

### Python Modules

```bash
# Install dependencies
pip install flask flask-cors psutil

# Run log analysis
cd securops-automation/python
python log_parser.py /path/to/logfile.log
python anomaly_detector.py
python log_aggregator.py

# Run integration monitoring
cd identityops/python
python log_retriever.py
python service_monitor.py
python uptime_tracker.py
```

### Dashboards

**Health Monitor (SecurOps):**
```bash
# Backend
cd securops-automation/health-monitor/backend
pip install -r requirements.txt
python app.py  # Runs on port 5000

# Frontend
cd securops-automation/health-monitor/frontend
npm install
npm run dev  # Runs on port 3000
```

**Integration Dashboard (IdentityOps):**
```bash
# Backend
cd identityops/dashboard/backend
pip install -r requirements.txt
python app.py  # Runs on port 5001

# Frontend (same structure)
cd identityops/dashboard/frontend
npm install
npm run dev
```

---

## 📁 Project Structure

```
SecureOps/
├── securops-automation/          # System auditing & log analysis
│   ├── powershell/
│   │   ├── Audit-SecurityEvents.ps1
│   │   ├── Scan-FilePermissions.ps1
│   │   └── Audit-Services.ps1
│   ├── python/
│   │   ├── log_parser.py
│   │   ├── anomaly_detector.py
│   │   └── log_aggregator.py
│   └── health-monitor/
│       ├── backend/
│       └── frontend/
│
├── identityops/                  # User provisioning & integration monitoring
│   ├── powershell/
│   │   ├── New-UserAccount.ps1
│   │   ├── Audit-Permissions.ps1
│   │   └── Sync-UserGroups.ps1
│   ├── python/
│   │   ├── log_retriever.py
│   │   ├── service_monitor.py
│   │   └── uptime_tracker.py
│   └── dashboard/
│       ├── backend/
│       └── frontend/
│
└── README.md
```

---

## 📊 Script Details

### SecurOps PowerShell Scripts

#### Audit-SecurityEvents.ps1
Parses Windows Security Event Log for critical security events.

```powershell
.\Audit-SecurityEvents.ps1 [-Hours <int>] [-OutputPath <string>] [-Critical]
```

- Monitors 20+ event types (logon, account changes, privilege use, policy changes)
- Categorizes by severity (Critical, Warning, Info)
- Exports to JSON for dashboard integration

#### Scan-FilePermissions.ps1
Scans directories for permission vulnerabilities.

```powershell
.\Scan-FilePermissions.ps1 [-Path <string>] [-Depth <int>] [-OutputPath <string>] [-IncludeFiles]
```

- Detects risky permissions (Everyone with write access)
- Identifies orphaned SIDs
- Flags broken inheritance

#### Audit-Services.ps1
Audits Windows services status.

```powershell
.\Audit-Services.ps1 [-CriticalOnly] [-OutputPath <string>] [-CustomCritical <string[]>]
```

- Monitors 20+ critical system services
- Detects non-standard service accounts
- Alerts on stopped critical services

### IdentityOps PowerShell Scripts

#### New-UserAccount.ps1
Automated user account provisioning.

```powershell
.\New-UserAccount.ps1 -Username <string> -FullName <string> [-Groups <string[]>] [-Department <string>] [-PasswordPolicy <Standard|Complex|Temporary>] [-CreateHomeDir]
```

- Creates local user accounts with group assignments
- Generates secure passwords based on policy
- Creates audit trail

#### Audit-Permissions.ps1
Comprehensive permission auditing.

```powershell
.\Audit-Permissions.ps1 [-Scope <Users|Groups|All>] [-IncludeDisabled] [-PrivilegedOnly] [-MaxInactiveDays <int>]
```

- Analyzes user/group memberships
- Risk-level assessment for privileged access
- Generates actionable recommendations

#### Sync-UserGroups.ps1
Role-based group synchronization.

```powershell
.\Sync-UserGroups.ps1 -Username <string> [-Template <IT|HR|Finance|Developer|Manager|Standard>] [-Groups <string[]>] [-RemoveExisting]
```

- Predefined role templates (IT, HR, Finance, etc.)
- Bulk updates from CSV/JSON files
- Protected group safeguards

---

## 🛡️ Security Considerations

- **Administrative Privileges**: Most scripts require elevated permissions
- **Audit Logging**: All operations are logged for compliance
- **Protected Groups**: Critical groups (Administrators, Domain Admins) are protected from automatic changes
- **Credential Handling**: Passwords are generated using cryptographic randomness

---

## 📝 License

MIT License - See LICENSE file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

Built with ❤️ by SecurOps Team