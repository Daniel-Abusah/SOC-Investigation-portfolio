# The Finance Trail: Phishing, Persistence and Network Staging

**Type:** Simulated SOC investigation  
**Platform:** Splunk  
**Evidence:** Nginx, mail, Windows/Sysmon, Suricata and Samba logs  
**Investigation date in dataset:** 9 October 2026

## Investigation objective

I investigated a simulated finance-workstation compromise by connecting email and web activity with endpoint execution, persistence, outbound communications and file staging. The main challenge was identifying which events belonged to the same activity without confusing normal finance processes with suspicious ones.

## Preparation and approach

I first inventoried the available indexes and examined raw events to understand their formats. The lab used `finance_web`, `finance_mail`, `finance_endpoint`, `finance_network` and `finance_files`. Windows event fields were embedded in XML; several network fields were nested in Suricata JSON. I correlated evidence using the host, process image, hash, PID and time, source IP and port, and file names.

```spl
| tstats count WHERE index=* BY index sourcetype
| sort - count
```

```spl
index=finance_network
| spath
| table timestamp event_type src_ip dest_ip _raw
```

## Findings

### 1. Phishing-related web and endpoint activity

The investigation identified a ZIP download associated with `lawson-rowe-review.com/downloads/Disclosure_Schedule_Update.zip`. The workstation's Chrome process was launched by `VantaraFinancePortal.exe`, based on the Sysmon parent-image evidence. I used mail and web records together rather than assuming the mail client was the browser's immediate parent.

```spl
index=finance_mail "lawson-rowe-review.com"
| table _time _raw
```

```spl
index=finance_endpoint "lawson-rowe-review.com"
| rex field=_raw "Name=['\"]Image['\"]>(?<image>[^<]+)"
| rex field=_raw "Name=['\"]ParentImage['\"]>(?<parent>[^<]+)"
| table _time image parent
```

### 2. Loader correlation and persistence

The loader `ledgerdrop.exe` and installed executable `VantaraSync.exe` shared a SHA-256 value beginning `AAD4B231C4AFC7D02A09344545A957086`. Only the prefix was preserved in the retained notes, so I have not published a fabricated full hash. The suspicious scheduled task was `VantaraUpdateCheck`, created through `schtasks.exe` in the loader's process lineage. I distinguished it from the routine `FinanceTemplateRefresh` task.

```spl
index=finance_endpoint "Hashes"
| rex field=_raw "Name=['\"]Image['\"]>(?<image>[^<]+)"
| rex field=_raw "Name=['\"]Hashes['\"]>(?<hashes>[^<]+)"
| rex field=hashes "(?i)SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| where isnotnull(sha256)
| stats values(image) AS executables dc(image) AS unique_paths BY sha256
| where unique_paths > 1
```

```spl
index=finance_endpoint "schtasks.exe"
| rex field=_raw "Name=['\"]CommandLine['\"]>(?<command>[^<]+)"
| rex field=command "(?i)/TN\s+[\"']?(?<task_name>[^\"'\s]+)"
| table _time task_name command
```

### 3. Outbound callback

Sysmon recorded creation of `VantaraSync.exe` at `02:33:25.981` UTC. The first relevant Nginx callback to `cdn-lawsonreview.net/sync/v4/check` was at `02:34:13.000`, a difference of **47.019 seconds**, reported as **47 whole seconds** in the challenge. The first corresponding local TCP source port was **50611**, corroborated using Suricata and Windows Filtering Platform Event ID 5156.

```spl
index=finance_network
| spath
| search src_ip="10.81.70.254"
| where 'http.hostname'="cdn-lawsonreview.net"
| table timestamp src_ip src_port dest_ip dest_port http.url
| sort timestamp
```

### 4. PID reuse and archive staging

A PowerShell process later used PID `692` to run `Compress-Archive`. The last previously recorded executable with that PID on workstation `VAN-FIN-WS-014` was `elevation_service.exe`. This illustrates **PID reuse**, not a parent-child relationship.

Sysmon Event ID 11 recorded creation of `review_notes_2026.zip` at `02:53:29.688` UTC. Suricata recorded a successful SMB2 WRITE to `10.81.72.63:445` at `02:53:40.986626` UTC. The elapsed time was **11.298626 seconds**, or **11 whole seconds** for the challenge response. This supports staging to an internal file share; it does **not** by itself prove external exfiltration.

```spl
index=finance_endpoint "review_notes_2026.zip"
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| rex field=_raw "Name=['\"]UtcTime['\"]>(?<utc_time>[^<]+)"
| rex field=_raw "Name=['\"]TargetFilename['\"]>(?<filename>[^<]+)"
| where event_id="11"
| table _time utc_time filename
```

```spl
index=finance_network "review_notes_2026.zip"
| spath
| table timestamp event_type src_ip dest_ip dest_port smb _raw
| sort timestamp
```

## Troubleshooting and lessons learned

| Initial issue | Correction |
|---|---|
| Web `request_uri` was blank | Inspected raw Nginx JSON and used the `uri` field |
| Assuming Outlook directly launched Chrome | Checked Sysmon `ParentImage` |
| Calculated 43 seconds for the callback | Used the precise Sysmon Event ID 1 process creation time and obtained 47 seconds |
| DNS answers appeared blank | Inspected nested `dns.answers` in Suricata JSON |
| Mistook SMB fileinfo for a successful write | Filtered for the successful SMB2 WRITE event |
| Regex produced an unmatched parenthesis error | Simplified process-image matching with `like(lower(image), "%powershell.exe")` |

## Outcome

This exercise strengthened my ability to build an evidence-based incident timeline across mail, web, endpoint and network sources. The most useful lesson was to validate timestamps and raw event fields before interpreting correlations. A shared PID or similar filename is not enough on its own to establish a causal relationship.

## Evidence and limitations

This write-up is based on my retained lab investigation notes. Full original log exports and screenshots are not included here. Some hashes and headers were not preserved in full and have deliberately been omitted. The sample SPL queries are reproducible starting points for the lab dataset; they are not claims that every query executed successfully without modification.

## Reconstructed activity

The retained findings suggest a sequence from phishing-related download activity to loader execution, scheduled task persistence, an outbound callback and archive staging over SMB. This is an analytical reconstruction, not proof of every causal link. The full process GUID chain and original mail headers would be needed to validate those links.

## Assessment and next steps

The reported shared hash supports a relationship between the two executables, but the incomplete retained hash prevents independent verification. The HTTP callback is consistent with suspected command and control; its purpose is not established by timing alone. The successful SMB write supports internal staging, but does not establish onward transfer or the contents of the archive.

See the [timeline](incident-timeline.md), [detection recommendations](detection-recommendations.md) and [response recommendations](incident-response.md) for follow-up work.
