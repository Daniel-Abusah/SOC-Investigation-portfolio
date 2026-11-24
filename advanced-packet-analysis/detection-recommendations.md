# Detection and response recommendations

| Signal | Detection approach | Validation / response |
|---|---|---|
| Horizontal scan | Count distinct destinations per source in a time window | Baseline approved scanners |
| HTTP beacon | Repeated URI, destination and similar sizes; assess intervals | Correlate process and proxy logs |
| Reverse shell | Unusual outbound port and command interpreter network activity | Isolate affected endpoint if confirmed |
| Disguised executable | Compare MIME, extension and magic bytes | Quarantine and hash safely |
| Archive POST | Correlate archive creation with outbound HTTP uploads | Review DLP and proxy evidence |
| DNS tunnel | Long labels, high unique-label counts and common suffix | Baseline CDNs and legitimate telemetry |
| TLS fingerprint | Correlate JA4, destination and certificate attributes | Avoid fingerprint-only blocking |
| FTP | Alert on cleartext authentication | Replace with SFTP or FTPS; rotate exposed credentials |

Preserve capture and endpoint evidence, validate scope, then contain confirmed compromise. Use the IoC extraction pipeline for triage, not automatic attribution. These are proposed detections, not deployed or tested rules.
