# Network Monitoring with Zeek — SOC Investigation & Detection Tuning

**Hands-on forensic case study | TryHackMe lab | November 2026**

> This repository documents a controlled training-lab investigation. The IP addresses, domains, hashes, and conclusions below are observations from the supplied lab artifacts, not independently verified real-world threat attributions. No packet captures or live traffic are redistributed.

## Overview

We investigated suspicious SMB connection attempts, repeated HTTPS traffic, DNS TXT queries, an HTTP upload, TLS metadata, file masquerading, and hash-based threat intelligence. We then tuned a Zeek DNS detection script to suppress legitimate DNS validation traffic while retaining suspicious notices.

**Highlights:** 23 baseline notices → **10** after suppressing `10.0.0.53` (13 fewer, **56.5%** reduction). The original source distribution was 13 notices for `10.0.0.53` and 10 for `10.14.22.88`. The final count of 10 was accepted by the lab; the screenshot set documents the baseline and debugging, but does **not** contain a terminal screenshot of the successful final tuned run.

## Repository contents

- [Full investigation walkthrough](INVESTIGATION.md) — questions, commands, verified outputs, forensic interpretation, and troubleshooting.
- [Evidence index](EVIDENCE.md) — 24 original terminal screenshots, organized by investigation step.
- [Command cheat sheet](COMMANDS.md) — reusable Zeek commands and cross-log pivots.
- [`screenshots/`](screenshots/) — the original screenshots used during the exercise.

## Incident snapshot

| Artifact | Observation |
|---|---|
| Suspicious source | `10.14.22.88` |
| Repeated HTTPS destination | `194.165.16.56` (`update.softpatch-cdn.com`) |
| Last observed matching TCP/443 timestamp | `1763092746.812696` |
| TLS sessions to destination with missing SNI | **82** |
| Long DNS queries | **18** `TXT` queries to `exfil-channel.net` |
| HTTP exfiltration destination | `185.213.154.201` (`backup.corpfiles-sync.com`) |
| POST | `03:15:07 UTC`, `/upload/data` |
| HTTP request body | **5,348,721 bytes** |
| Originator application bytes | **5,348,913 bytes** (difference **192**) |
| Uploaded filename | `backup_archive.zip` |
| Threat-feed family label | `CobaltStrikeStager` (local feed, high confidence) |
| Disguised file | `invoice_march.pdf` → `application/x-dosexec` |
| HTTP responder body | **7 bytes** (confirmed via `http.log`) |
| Detection baseline → tuned | **23 → 10** notices |

## Investigation method

`conn.log` → `dns.log` → `http.log` / `ssl.log` → `files.log` → local threat feed → custom Zeek notice script.

Use Zeek's **`uid`** to correlate connection and HTTP events, and file **`conn_uids`** where present. DNS name-to-IP mapping requires matching the `answers` field, not merely picking the closest query timestamp.

## Reproducing

The training environment used `/home/ubuntu` as the working directory, with `logs/`, `pcaps/finance-sensor.pcap`, `scripts/dns_notice.zeek`, and `threat-feed.csv`. Those lab files are **not** included here. Commands in this repository assume access to the same authorized lab environment.

## Ethical scope

All observations are from a security-training environment. Do not interpret this repository as evidence against the real-world owners of the example IP addresses or domains.
