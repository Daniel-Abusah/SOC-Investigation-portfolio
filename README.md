# SOC Investigation Portfolio

A collection of hands-on security investigations, threat hunting exercises, cyber threat intelligence assessments and network forensics labs.

This repository documents my practical work with security monitoring tools, log analysis, incident investigation and detection engineering. I use these exercises to strengthen my understanding of how security incidents develop, how evidence can be correlated across different sources and how analysts can distinguish suspicious activity from legitimate system behaviour.

My focus is on understanding the investigation process, not simply arriving at the correct answer.

## Portfolio Overview

| Investigation | Primary Tools | Technical Focus |
|---|---|---|
| [Network Monitoring with Zeek](Zeek-Network-Forensics/README.md) | Zeek, Bash, Linux | Network forensics and detection tuning |
| [Threat Hunting with Zui](Zui-Threat-Hunting/) | Zui, Zeek, Zed | Beaconing, exfiltration and lateral movement |
| [Advanced Packet Analysis](advanced-packet-analysis/) | Wireshark, TShark, OpenSSL | Packet analysis and forensic evidence extraction |
| [Trooper: Unmasking APT X](Trooper-Unmasking-APT-X/) | OpenCTI, MITRE ATT&CK | Threat intelligence and adversary profiling |
| [Finance Trail](finance-trail/README.md) | Splunk, Sysmon, Suricata | Incident investigation and attack reconstruction |

## Selected Investigation Findings

- Reduced Zeek notices from 23 to 10 by excluding known legitimate DNS validation traffic while retaining notices associated with the suspicious host.
- Identified reconnaissance activity targeting 87 unique internal destinations during a packet-level investigation.
- Identified 23 plaintext HTTP beacons associated with a compromised workstation.
- Extracted a disguised executable and correlated its SHA256 hash with a local threat intelligence feed that identified it as Cobalt Strike.
- Identified 40 long DNS queries associated with suspected DNS tunnelling.
- Used a Bash-based IOC extraction pipeline to identify eight unique external destination IP addresses.
- Reconstructed attacker activity by correlating endpoint, network and file creation events.

These findings relate to the supplied training datasets and are documented within the relevant investigations.

## Investigations

### 1. Network Monitoring with Zeek

**Focus:** Network forensics, traffic analysis, data exfiltration and detection tuning

**Tools:** Zeek, Linux, Bash

**Environment:** TryHackMe

Investigated suspicious network activity using Zeek connection, DNS, HTTP, TLS and file analysis logs.

The investigation covered:

- Repeated outbound HTTPS connections and possible C2 beaconing.
- DNS tunnelling indicators involving unusually long queries.
- HTTP POST activity associated with a suspicious file upload.
- File extension and MIME type mismatches.
- SHA256 hash correlation with a local threat intelligence feed.
- Detection script tuning to suppress legitimate DNS server activity.

One of the practical exercises involved reducing Zeek notices from 23 to 10 while retaining notices associated with the suspicious host.

**[View investigation](Zeek-Network-Forensics/README.md)**

---

### 2. Threat Hunting with Zui

**Focus:** Network threat hunting and evidence correlation

**Tools:** Zui, Zeek, Zed Query Language

**Environment:** TryHackMe

Investigated suspicious network activity using an iterative, query-driven approach. The investigation focused on C2 beaconing, data exfiltration and potential lateral movement.

The investigation covered:

- Identifying hosts with unusual outbound connection patterns.
- Examining TLS connections and server names.
- Investigating large outbound data transfers.
- Correlating HTTP requests with extracted file metadata.
- Examining unanswered SMB connection attempts.
- Investigating potential lateral movement using LDAP and SMB traffic.

This exercise helped me understand how investigative hypotheses can be refined through successive queries and evidence correlation.

**[View investigation](Zui-Threat-Hunting/)**

---

### 3. Advanced Packet Analysis and Network Forensics

**Focus:** Packet-level investigation, forensic artifact extraction and protocol abuse

**Tools:** Wireshark, TShark, OpenSSL, Bash, Linux

**Environment:** TryHackMe

Conducted a packet-level investigation to identify network reconnaissance, C2 beaconing, reverse shell activity, disguised malware and data exfiltration.

The investigation covered:

- Network reconnaissance and connection analysis.
- HTTP beaconing and Base64 decoding.
- TCP stream reconstruction.
- HTTP object extraction and file signature verification.
- SHA256 hash generation and threat intelligence correlation.
- TLS certificate analysis and JA4 fingerprinting.
- DNS tunnelling detection.
- Automated IOC extraction using a supplied Bash script.

This investigation demonstrated the value of examining packet-level evidence when conventional security logs do not provide sufficient detail.

**[View investigation](advanced-packet-analysis/)**

---

### 4. Trooper: Unmasking APT X

**Focus:** Cyber threat intelligence and adversary profiling

**Tools:** OpenCTI, MITRE ATT&CK

**Environment:** TryHackMe

Investigated an advanced persistent threat using threat intelligence sources to examine its activities, associated malware, infrastructure and attack techniques.

The exercise involved identifying:

- Phishing techniques associated with the threat actor.
- Known vulnerabilities exploited during attacks.
- Malware and remote access tools linked to the group.
- Persistence mechanisms and suspicious registry modifications.
- Relevant MITRE ATT&CK techniques.

The investigation helped me practise connecting individual indicators and techniques to a broader adversary profile.

**[View investigation](Trooper-Unmasking-APT-X/)**

---

### 5. Finance Trail: Security Investigation

**Focus:** Incident investigation, event correlation and forensic analysis

**Tools:** Splunk, Sysmon, Suricata

**Environment:** TryHackMe

A practical investigation involving suspicious activity in a financial environment.

The case study covers the use of security telemetry to reconstruct attacker activity, correlate events across different log sources and establish an evidence-based timeline.

Particular attention was given to:

- Initial access and suspicious file downloads.
- Process execution and parent-child relationships.
- Scheduled task activity.
- Command and control communications.
- File creation and archive staging.
- Data movement between systems.
- Timestamp correlation across endpoint and network logs.

**[View case study](finance-trail/README.md)**

---

## Tools and Technical Areas

| Area | Tools and Techniques |
|---|---|
| SIEM and log analysis | Splunk, Elastic, SPL |
| Network monitoring | Zeek, Suricata |
| Packet analysis | Wireshark, TShark |
| Threat hunting | Zui, Zed Query Language |
| Endpoint investigation | Sysmon, Windows event logs |
| Threat intelligence | OpenCTI, MISP, MITRE ATT&CK |
| Digital forensics | File extraction, SHA256 hashing, file signature analysis |
| TLS analysis | OpenSSL, certificate inspection, JA4 fingerprinting |
| Operating systems | Linux, Windows |
| Scripting and automation | Bash, Zeek scripting |
| Security operations | Incident triage, IOC analysis, event correlation, detection tuning |
| Version control | Git, GitHub |

These reflect tools and techniques I have worked with through practical exercises and technical training. My proficiency varies across them, and I continue to build experience through additional investigations.

## Investigation Approach

Although each case is different, I generally follow a similar process:

1. **Understand the scenario.** Identify the reported activity, available evidence and questions that need answering.
2. **Establish a baseline.** Where sufficient data is available, review normal activity and identify unusual connections, processes, authentication events or file operations.
3. **Investigate the evidence.** Use relevant queries and tools to narrow down suspicious events.
4. **Correlate findings.** Compare timestamps, hosts, connection identifiers and other indicators across available logs.
5. **Validate conclusions.** Check that findings are supported by evidence and distinguish confirmed activity from assumptions.
6. **Document the investigation.** Record useful commands, findings, unsuccessful approaches and lessons learned.

I also document commands that initially fail when the troubleshooting process offers something worth learning.

## About Me

I have a background in Information Technology, including IT support, systems administration and regulatory compliance.

My experience supporting users and troubleshooting technical issues has influenced how I approach security investigations: establish what happened, examine the available evidence and work methodically towards an explanation.

I am currently undertaking TryHackMe SOC Level 2 training and building my practical experience in security operations, incident response, threat intelligence and digital forensics.

This repository will continue to grow as I complete and document additional investigations.

## Professional Profiles

- [GitHub Profile](https://github.com/Daniel-Abusah)
- [TryHackMe Profile](https://tryhackme.com/p/danielkwammy)

---

*The investigations in this repository were conducted in authorised training and lab environments. Findings relate to the supplied scenarios and datasets unless otherwise stated.*