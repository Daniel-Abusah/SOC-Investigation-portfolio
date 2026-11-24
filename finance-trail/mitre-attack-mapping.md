# Proposed MITRE ATT&CK mapping

These mappings are analyst interpretations of the retained findings, not independently verified technique detections.

| Technique | ID | Basis and caveat |
|---|---|---|
| Spearphishing Link | T1566.002 | Phishing-related download; verify message and link delivery |
| Scheduled Task | T1053.005 | Reported suspicious task; verify creation and configured action |
| Web Protocols | T1071.001 | Suspected HTTP C2 callback; verify command and control purpose |
| PowerShell | T1059.001 | Reported Compress-Archive execution |
| Archive via Utility | T1560.001 | Reported archive creation; verify command and collected contents |
| Remote Data Staging | T1074.002 | Internal SMB transfer consistent with staging; verify destination file |

Technique IDs are proposed from standard ATT&CK terminology and were not live-verified for this revision. No external exfiltration technique is assigned because onward transfer was not established.
