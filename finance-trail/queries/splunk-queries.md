# SPL investigation reference

Original searches retained from the case study. They are starting points, not verified executable tests. Set the time picker to the dataset date and confirm field names in raw events.

## Index inventory

```spl
| tstats count WHERE index=* BY index sourcetype
| sort - count
```

## Network field discovery

```spl
index=finance_network
| spath
| table timestamp event_type src_ip dest_ip _raw
```

## Mail pivot

```spl
index=finance_mail "lawson-rowe-review.com"
| table _time _raw
```

## Browser parent

```spl
index=finance_endpoint "lawson-rowe-review.com"
| rex field=_raw "Name=['\"]Image['\"]>(?<image>[^<]+)"
| rex field=_raw "Name=['\"]ParentImage['\"]>(?<parent>[^<]+)"
| table _time image parent
```

## Hash correlation

```spl
index=finance_endpoint "Hashes"
| rex field=_raw "Name=['\"]Image['\"]>(?<image>[^<]+)"
| rex field=_raw "Name=['\"]Hashes['\"]>(?<hashes>[^<]+)"
| rex field=hashes "(?i)SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| where isnotnull(sha256)
| stats values(image) AS executables dc(image) AS unique_paths BY sha256
| where unique_paths > 1
```

## Scheduled task discovery

```spl
index=finance_endpoint "schtasks.exe"
| rex field=_raw "Name=['\"]CommandLine['\"]>(?<command>[^<]+)"
| rex field=command "(?i)/TN\s+[\"']?(?<task_name>[^\"'\s]+)"
| table _time task_name command
```

## Callback network pivot

```spl
index=finance_network
| spath
| search src_ip="10.81.70.254"
| where 'http.hostname'="cdn-lawsonreview.net"
| table timestamp src_ip src_port dest_ip dest_port http.url
| sort timestamp
```

## Archive creation

```spl
index=finance_endpoint "review_notes_2026.zip"
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| rex field=_raw "Name=['\"]UtcTime['\"]>(?<utc_time>[^<]+)"
| rex field=_raw "Name=['\"]TargetFilename['\"]>(?<filename>[^<]+)"
| where event_id="11"
| table _time utc_time filename
```

## SMB event discovery

```spl
index=finance_network "review_notes_2026.zip"
| spath
| table timestamp event_type src_ip dest_ip dest_port smb _raw
| sort timestamp
```

## Proposed scheduled task lineage refinement

```spl
index=finance_endpoint "schtasks.exe"
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| where event_id="1"
| rex field=_raw "Name=['\"]Image['\"]>(?<image>[^<]+)"
| rex field=_raw "Name=['\"]ParentImage['\"]>(?<parent_image>[^<]+)"
| rex field=_raw "Name=['\"]ProcessGuid['\"]>(?<process_guid>[^<]+)"
| rex field=_raw "Name=['\"]ParentProcessGuid['\"]>(?<parent_guid>[^<]+)"
| rex field=_raw "Name=['\"]CommandLine['\"]>(?<command>[^<]+)"
| search command="*VantaraUpdateCheck*"
| table _time host image parent_image process_guid parent_guid command
| sort 0 _time
```

Pivot on the parent GUID in additional process creation events on the same host to reconstruct ancestry. This search is untested and XML formatting may require adjustments.

## Further validation

The callback search uses Suricata fields; it does not itself reproduce the Nginx timestamp. Inspect the raw Nginx record in `finance_web` and compare with WFP 5156. The SMB search discovers events but does not explicitly prove successful WRITE status; inspect the operation, response status and transaction identifiers in the raw event. Hash grouping should be scoped by host and time when establishing relationships. For PID reuse, filter process creation events to the same host and PID, sort by UTC creation time and select the immediately preceding event. Do not infer ancestry from PID reuse.

## Troubleshooting and lessons learned

| Initial issue | Correction |
|---|---|
| Web `request_uri` was blank | Inspected raw Nginx JSON and used the `uri` field |
| Assuming Outlook directly launched Chrome | Checked Sysmon `ParentImage` |
| Calculated 43 seconds for the callback | Used the precise Sysmon Event ID 1 process creation time and obtained 47 seconds |
| DNS answers appeared blank | Inspected nested `dns.answers` in Suricata JSON |
| Mistook SMB fileinfo for a successful write | Filtered for the successful SMB2 WRITE event |
| Regex produced an unmatched parenthesis error | Simplified process-image matching with `like(lower(image), "%powershell.exe")` |


Exact failed searches were not retained in the supplied report; the table records the known failure modes rather than inventing commands.
