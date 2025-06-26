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
```
