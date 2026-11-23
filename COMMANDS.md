# Zeek quick-reference commands

Run from `/home/ubuntu` unless absolute paths are used.

```bash
# Inspect source/destination/connection states
zeek-cut ts id.orig_h id.resp_h id.resp_p proto conn_state < logs/conn.log | head

# First SMB S0 attempt by suspect
zeek-cut ts id.orig_h id.resp_h id.resp_p proto conn_state < logs/conn.log | awk '$2=="10.14.22.88" && $4=="445" && $5=="tcp" && $6=="S0"' | sort -n -k1,1 | head -1

# Latest TCP/443 contact
zeek-cut ts id.orig_h id.resp_h id.resp_p proto < logs/conn.log | awk '$2=="10.14.22.88" && $3=="194.165.16.56" && $4=="443" && $5=="tcp"' | sort -n -k1,1 | tail -1

# DNS records and domain/IP resolution
zeek-cut id.orig_h query qtype_name < logs/dns.log | awk '$1=="10.14.22.88" && $2 ~ /exfil-channel\.net/ {print $3}' | sort | uniq -c
zeek-cut ts id.orig_h query answers < logs/dns.log | grep '185.213.154.201'
zeek-cut ts query answers < logs/dns.log | grep '194.165.16.56'

# HTTP POST metadata and body length
zeek-cut uid ts id.orig_h id.resp_h method uri request_body_len response_body_len < logs/http.log | grep '185.213.154.201'

# TLS empty SNI count
zeek-cut id.resp_h server_name < logs/ssl.log | awk '$1=="194.165.16.56" && ($2=="-" || $2=="")' | wc -l

# File types, size, and SHA256
zeek-cut fuid filename mime_type seen_bytes total_bytes sha256 < logs/files.log | grep -E 'invoice_march.pdf|backup_archive.zip'

# Local threat-feed lookup
HASH=$(zeek-cut filename sha256 < logs/files.log | awk '$1=="backup_archive.zip" {print $2; exit}')
grep -iF "$HASH" threat-feed.csv

# Notice counts and per-host breakdown
zeek-cut note < notice.log | wc -l
zeek-cut id.orig_h < notice.log | sort | uniq -c
```

**Troubleshooting:** Always confirm file/script paths with `find` or `ls`, and verify `notice.log` exists before counting. A shell redirection failure followed by `0` is not a valid zero-notice finding. For response body length, `http.log` may provide the answer even when `files.log` has no matching `conn_uids` entry. Prefer UID joins and verified DNS `answers` over timestamp proximity.
