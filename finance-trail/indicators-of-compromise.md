# Indicators and investigation context

All values below come from the simulated case study. Domains are shown as code for reference, not as links.

| Type | Value | Context |
|---|---|---|
| Domain | `lawson-rowe-review.com` | Phishing-related activity |
| URL path | `/downloads/Disclosure_Schedule_Update.zip` | Associated download |
| Domain | `cdn-lawsonreview.net` | Suspected callback infrastructure |
| URI | `/sync/v4/check` | Callback path |
| File | `ledgerdrop.exe` | Reported loader |
| File | `VantaraSync.exe` | Reported installed executable |
| Task | `VantaraUpdateCheck` | Suspicious persistence |
| File | `review_notes_2026.zip` | Staged archive |
| SHA-256 prefix | `AAD4B231C4AFC7D02A09344545A957086` | Incomplete; not suitable for exact hash matching |

## Correlation context (not standalone IOCs)

| Field | Value |
|---|---|
| Workstation | `VAN-FIN-WS-014` |
| Source IP used in callback search | `10.81.70.254` |
| SMB destination | `10.81.72.63:445` |
| Local TCP source port | `50611` |
| Reused PID | `692` |
| Previous executable with PID | `elevation_service.exe` |
| Routine comparison task | `FinanceTemplateRefresh` |

Do not block legitimate executables, internal addresses or ephemeral ports solely on these values. Recover the complete hash and validate scope before operational use.
