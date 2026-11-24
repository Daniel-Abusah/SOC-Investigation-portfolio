# Incident timeline

Dataset date: 9 October 2026. Times are UTC as recorded in the retained report.

| Time | Source | Activity |
|---|---|---|
| 02:33:25.981 | Sysmon | VantaraSync.exe process creation |
| 02:34:13.000 | Nginx | First relevant callback |
| 02:53:29.688 | Sysmon Event 11 | review_notes_2026.zip creation |
| 02:53:40.986626 | Suricata | Reported successful SMB2 WRITE |

## Timing calculations

- Callback minus process creation: 47.019 seconds (47 whole seconds).
- SMB write minus archive creation: 11.298626 seconds (11 whole seconds).

These calculations were checked against the retained timestamps, not original logs. Validate clock alignment, event semantics and timezone handling before using such intervals in a production incident. Exact times for the earlier download, loader and task creation were not retained; they are not assigned invented timestamps.
