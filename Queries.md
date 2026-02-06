# Overwatch Queries

#### Windows Defender Disabled

```
"<hostname>" &&  ("Sophos"|| "Huntress" || "SentinelOne" || "Bitdefender" || "CrowdStrike" || "Cisco" || "McAfee" || "Trend" || "Fortinet" || "Cybereason" || "Rapid7" || "Cylance")
```
```
"<hostname>" && ("Definition Updates")
```
```
"<hostname>" &&(action: "Dns query:")
```
#### Lateral Movement

```
(action: "Dns query:") && "<account>" && "<hosts>" && !(eventid: 4634 || 4624)
```
```
alerttype: sharemapping
```
```
Elevated Token: Yes == %%1842
```

####  DCSync Activity
```
"mimikatz" || "mimi" || "dump" || "dumping" || "replication" && !(description: "file replication service") && !(sub_type: "windows_logon_success")
```

####  User Authentication / Login (Entra ID Sign‑in Logs)
```
action: "UserLoggedIn"
action: "UserLoginFailed"
action: "InteractiveSignIn"
action: "NonInteractiveSignIn"
action: "ServicePrincipalSignIn"

logCategory: "SignInLogs"
authenticationRequirement: "multiFactorAuthentication"
authenticationRequirement: "singleFactorAuthentication"

status: "Success"
status: "Failure"

errorCode: "0"
errorCode: "50126"        // Invalid credentials
errorCode: "50076"        // MFA required
errorCode: "50074"        // MFA challenge failed

conditionalAccessStatus: "success"
conditionalAccessStatus: "failure"
conditionalAccessStatus: "notApplied"

clientAppUsed: "Browser"
clientAppUsed: "Mobile Apps and Desktop clients"
clientAppUsed: "Exchange ActiveSync"

resource: "Microsoft 365"
resource: "Azure Portal"
resource: "SharePoint Online"

riskLevelAggregated: "low"
riskLevelAggregated: "medium"
riskLevelAggregated: "high"
```

####  SharePoint Online & OneDrive Access (Unified Audit Log)
```
workload: "SharePoint"
recordType: "SharePointFileOperation"

action: "FileAccessed"
action: "FileDownloaded"
action: "FileUploaded"
action: "FileDeleted"
action: "FileModified"
action: "FilePreviewed"

action: "FolderCreated"
action: "FolderDeleted"

action: "SharingSet"
action: "SharingInvitationCreated"
action: "AnonymousLinkCreated"
action: "AnonymousLinkUsed"

objectType: "File"
objectType: "Folder"

accessType: "User"
accessType: "Anonymous"
accessType: "ExternalUser"
```

####  Email Access & Exchange Online Activity
```
workload: "Exchange"
recordType: "ExchangeAdmin"
recordType: "ExchangeItem"

action: "MailItemsAccessed"
action: "MessageBind"
action: "Send"
action: "SendOnBehalf"
action: "SendAs"

action: "MailboxLogin"
action: "MailboxLoginFailed"

action: "Set-Mailbox"
action: "New-InboxRule"
action: "Set-InboxRule"
action: "Remove-InboxRule"

logonType: "Owner"
logonType: "Delegate"
logonType: "Admin"

clientInfo: "Outlook"
clientInfo: "OWA"
clientInfo: "Exchange Web Services"
clientInfo: "IMAP4"
clientInfo: "POP3"
```

####  Other Application & Cloud App Access
```
logCategory: "AuditLogs"

action: "AddServicePrincipal"
action: "ConsentGranted"
action: "AddAppRoleAssignment"
action: "RemoveAppRoleAssignment"

action: "UpdateApplication"
action: "DeleteApplication"

resourceType: "Application"
resourceType: "ServicePrincipal"

appDisplayName: "Microsoft Teams"
appDisplayName: "Salesforce"
appDisplayName: "Zoom"
```

####  High‑Value Fields Commonly Used in SOC Detections
```
userPrincipalName: "user@domain.com"
userId: "GUID"
ipAddress: "x.x.x.x"
location: "PH"
location: "US"
location: "Unknown"

deviceDetail: "Windows"
deviceDetail: "iOS"
deviceDetail: "Android"

correlationId: "GUID"
requestId: "GUID"

userAgent: "Mozilla/5.0"
```

==========================================
==========================================

# HandOver Notes
```
Summary of current status/inquiry (what is the specific problem the customer requesting)?
What have I done/tested so far?
What is the expected outcome?
```

# Partner call request
```
Partner call request

Hello Black Team, 

Partner: 
Alert Name:
Alert ID: 
Jira Ticket: 
Involved Host: 
Involved Account: 
Privileged?: 
Threat Mitigated: 
Host Isolated?: 
Account Disabled?:
OSINT:

Alert Summary:


Reason for calling:
```

# Recurring
```
This is a recurring alert and requires validation, but it is not urgent. Please call during business hours.
```

# Persistence
```
"<>" && (eventid: 4698 || eventid: 4702 || eventid: 4657)
```
