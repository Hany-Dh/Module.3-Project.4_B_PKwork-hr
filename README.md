# PKWork Incident 8328: Multi-Stage Intrusion Investigation

![Severity](https://img.shields.io/badge/Severity-High-red)
![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-5E5E5E)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-blue)
![Type](https://img.shields.io/badge/Type-Training%20exercise-lightgrey)

> **CyberSteps | The PKWork Files | Individual project**
> Author: Hany Dhannoon | Report version 1.1 (Final) | 3 Nov 2026

Incident report for a multi-stage intrusion that started with phishing and ended with attacker-controlled administrator access in Okta, AWS and GCP. The investigation followed one user and one workstation across email, endpoint, identity, network and two clouds, then cross-checked the findings against the 17 alerts Sentinel grouped into the incident.

> **Disclaimer:** Training exercise. All data is lab data; IPs, accounts and keys are fictional.

---

## Objective

Investigate Incident 8328 (Microsoft Sentinel / Defender XDR), build the attack timeline, determine scope and impact, check detection coverage and recommend a prioritised response.

## Incident at a glance

| Field | Detail |
|---|---|
| Incident | 8328: High severity, Active, 17 alerts, 26 activities, 9 assets |
| Layers affected | Email, endpoint, Okta identity, network, AWS, GCP |
| Main actor | User `mirage` and IP `198.51.100.42`, seen in email, Okta, firewall, AWS and GCP data |
| Persistence | `backdoor-svc` (AWS), `backdoor-svc-gcp` (GCP), Okta "Backdoor API Token" |
| Exfiltration (likely) | 183 MB single upload to C2 `192.0.2.100` (99.99% of outbound bytes) |
| Data accessed | 6 sensitive cloud objects (finance, HR/PII, API keys): 3 in S3, 3 in GCS |
| Control gaps | 3 of 3 phishing emails delivered; 21 of 22 C2 flows allowed |

## Attack path

```
Phishing emails (3, SPF/DMARC fail, delivered to mirage)
  -> report.exe runs on win11a, C2 to 192.0.2.100
  -> Network sweep (83 hosts) and port scan (25 ports on 10.0.1.200)
  -> C2 beaconing, DNS tunnel, 183 MB upload
  -> Okta takeover from Moscow: super admin, backdoor token, CEO MFA reset
  -> AWS: backdoor-svc admin, CloudTrail deleted, 0.0.0.0/0 rule, 5 GPU instances, 3 S3 reads
  -> GCP: backdoor-svc-gcp Owner, log sinks removed, allow-all rule, 3 GPU VMs, 3 bucket reads
```

## Data sources analysed

| Source | Records |
|---|---|
| Firewall (Palo Alto) `CommonSecurityLog` | 149 |
| AWS CloudTrail | 47 |
| GCP audit logs | 25 |
| Email (MailGuard) | 3 |
| Endpoint (CrowdStrike detections) | 7 |
| Okta | 6 |
| Sentinel incident alerts | 17 |

## Tools and technologies

Microsoft Sentinel, Microsoft Defender XDR, KQL, CrowdStrike, Okta, Palo Alto firewall logs, AWS CloudTrail, GCP audit logs, MailGuard365, MITRE ATT&CK.

## MITRE ATT&CK coverage (selection)

| Tactic | Techniques |
|---|---|
| Initial access / execution | T1566 Phishing, T1078 Valid Accounts, T1204.002 User Execution |
| Credential access / persistence | T1556.006 MFA modification, T1136.003 Create Cloud Account, T1098 Account Manipulation |
| Discovery | T1018, T1046, T1087.004, T1580 |
| Command and control / exfiltration | T1071.001, T1071.004, T1572, T1041 |
| Defense evasion | T1562.007, T1562.008, T1036.005, T1070.001 |
| Collection / impact | T1530 Data from Cloud Storage, T1496 Resource Hijacking |

## Detection coverage

Most steps raised an alert, so **detection was good but blocking was weak**: the mail filter delivered all phishing emails despite 85 to 92% phishing scores, the firewall alerted once without blocking, and the EDR did not quarantine `report.exe`. Gaps remained for cloud data reads, GPU instance launches, DNS tunnelling and the reported server activity.

## Recommended response (summary)

1. **Cut attacker access:** revoke `mirage`; remove the Okta super-admin role, backdoor token and attacker authenticator; restore CEO MFA; disable both backdoor identities and their keys.
2. **Contain endpoint and C2:** isolate `win11a`, block the 4 IPs and 4 domains, purge the 3 emails, set the Block-Malicious rule to block.
3. **Close exposure and restore visibility:** remove both allow-all rules, snapshot then stop the 8 GPU instances, re-enable CloudTrail and the GCP log sinks.

The full prioritised plan (P0 to P2), automation guidance and a four-phase roadmap are in Section 6 of the report.

## Example KQL

Same user and infrastructure across sources:

```kql
search in (CommonSecurityLog, AWSCloudTrail, GCPAuditLogs)
  "198.51.100.42" or "203.0.113.77" or "185.220.101.55"
| summarize Events=count() by $table
```

Logging tampering in AWS:

```kql
AWSCloudTrail
| where EventName in ("StopLogging","DeleteTrail","AuthorizeSecurityGroupIngress","DisassociateIamInstanceProfile")
| project TimeGenerated, UserIdentityUserName, EventName, SourceIpAddress, RequestParameters
```

All reproduction queries are in **Section 4** of the report.

## Confidence and limitations

- **Confirmed:** phishing delivery, `report.exe` execution, the Okta takeover, firewall flows, cloud identity creation, logging tampering and data reads.
- **Likely, not proven:** the user's click, the 183 MB flow as exfiltration, mining, and the CEO and `jliu` being part of the incident.
- **Unknown:** contents of the 183 MB upload, data volume taken from the clouds, scope of `srv-dc01` and `srv-file01`.
- Source timestamps disagree (Feb to Oct 2026) and AWS events have no per-event time, so a single combined timeline is not possible. Early steps are ordered by lab stage numbers.
- File hashes in the data are placeholders and cannot identify real files.

## Repository contents

```
.
|-- README.md
|-- PKWork_Incident_8328_Report.pdf   # full 44-page report
`-- queries/                           # KQL queries from Section 4 (optional)
```

The report also contains an indicator register (Appendix B) and attacker-side cloud events (Appendix C).
