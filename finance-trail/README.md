# Finance Trail: SOC Investigation

A simulated finance workstation compromise investigated in Splunk using mail, Nginx, Sysmon, Suricata and Samba telemetry.

## Key findings

- Identified the browser parent process as `VantaraFinancePortal.exe` rather than Outlook.
- Correlated `ledgerdrop.exe` and `VantaraSync.exe` through a reported shared SHA-256 hash.
- Identified the suspicious `VantaraUpdateCheck` scheduled task.
- Calculated a 47.019-second interval between process creation and the first relevant callback.
- Identified PID reuse and an 11.298626-second interval between archive creation and an SMB write.

The SMB activity supports internal staging, not confirmed external exfiltration.

## Investigation documents

| Document | Purpose |
|---|---|
| [Investigation report](investigation-report.md) | Methodology, findings and limitations |
| [Incident timeline](incident-timeline.md) | Retained UTC timestamps |
| [Indicators](indicators-of-compromise.md) | Lab indicators and correlation context |
| [ATT&CK mapping](mitre-attack-mapping.md) | Proposed behavioural mappings |
| [Detection recommendations](detection-recommendations.md) | Detection opportunities and validation |
| [Incident response](incident-response.md) | Recommended response actions |
| [SPL queries](queries/splunk-queries.md) | Investigation searches and troubleshooting |

## Scope

This project documents an authorised training exercise. Findings are based on retained investigation notes; original logs and screenshots are not included. Proposed queries and detections have not been independently tested. Indicators belong to the simulated scenario and should not be treated as verified real-world threat intelligence.
