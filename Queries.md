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

# HandOver Notes
```
Summary of current status/inquiry (what is the specific problem the customer requesting)?
What have I done/tested so far?
What is the expected outcome?
```

# Partner call request
```
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
