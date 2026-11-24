# Advanced Packet Analysis

A hands-on SOC investigation of a simulated compromise using Wireshark, TShark, OpenSSL and Bash. I worked from the packet capture rather than relying only on log summaries.

## What I found
The capture contains a horizontal scan of 87 hosts, 23 HTTP beacons, a reverse shell, a disguised executable and an HTTP archive transfer. A supplied threat feed associates the executable with Cobalt Strike. I also identified suspicious DNS queries and a repeated TLS fingerprint.

## Project files
- [Investigation report](investigation-report.md)
- [Indicators of compromise](indicators-of-compromise.md)
- [Detection recommendations](detection-recommendations.md)
- [TShark reference](commands/tshark-reference.md)
- [Evidence screenshots](screenshots/)

## Scope
This is a TryHackMe training investigation, not a live incident. No PCAP, executable, archive or cleartext password is included. Findings are limited to the supplied lab evidence.
