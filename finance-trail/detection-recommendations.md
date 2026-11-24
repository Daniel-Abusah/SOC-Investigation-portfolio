# Detection recommendations

These are proposed detection opportunities, not deployed or tested rules.

| Behaviour | Telemetry | Validation and tuning |
|---|---|---|
| Unexpected browser parent | Sysmon 1 | Baseline approved portal and browser launch patterns; parent alone is not malicious |
| Scheduled task creation | Sysmon 1, Security 4698 | Inspect task action, creator, path and GUID lineage; compare approved tasks |
| Same hash in unexpected paths | Sysmon 1 | Require complete hash; exclude approved software deployment patterns |
| Archive creation by PowerShell | PowerShell 4104 (if enabled), Sysmon 1/11 | Correlate command, output file and user; exclude approved backup jobs |
| Suspicious HTTP callback | Proxy/Nginx, Suricata | Correlate destination, URI, endpoint and repeated timing; distinguish normal updates |
| Archive transfer over SMB | Suricata, Samba | Validate successful write, file identity and authorised share usage |
| Outbound process connection | Security 5156 | Correlate application, host, time and network tuple; do not alert on source port alone |

## Validation plan

Replay the lab searches if the dataset becomes available. Check field availability and event coverage, test against known benign activity, document false positives, and record results before promoting any search into a production alert.
