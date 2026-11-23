# SOC Investigation Portfolio

A collection of hands-on security investigations, threat intelligence exercises, and network forensics labs.

This repository documents my practical work with security monitoring tools, log analysis, incident investigation, and detection engineering. I use these exercises to strengthen my understanding of how security incidents develop, how evidence can be correlated across different sources, and how analysts can distinguish suspicious activity from legitimate system behaviour.

My focus is on understanding the investigation process, not simply arriving at the correct answer. Each case study includes the tools used, investigation steps, findings, and lessons learned.

## Investigations

### 1. Network Monitoring with Zeek

**Focus:** Network forensics, traffic analysis, data exfiltration, and detection tuning  
**Tools:** Zeek, Linux, Bash, PCAP analysis  
**Environment:** TryHackMe

Investigated suspicious network activity using Zeek connection, DNS, HTTP, TLS, and file analysis logs.

The investigation covered:

- Repeated outbound HTTPS connections and possible C2 beaconing.
- DNS tunnelling indicators involving unusually long TXT queries.
- HTTP POST activity associated with a suspicious file upload.
- File extension and MIME type mismatches.
- SHA256 hash correlation with a local threat intelligence feed.
- Detection script tuning to suppress legitimate DNS server activity.

One of the practical exercises involved reducing Zeek notices from 23 to 10 by excluding known legitimate DNS validation traffic while retaining notices associated with the suspicious host.

**[View investigation](Zeek-Network-Forensics/README.md)**

---

### 2. Trooper: Unmasking APT X

**Focus:** Threat intelligence and adversary profiling  
**Environment:** TryHackMe

Investigated an advanced persistent threat using threat intelligence sources to examine its activities, associated malware, infrastructure, and attack techniques.

The exercise involved identifying:

- Phishing techniques associated with the threat actor.
- Known vulnerabilities exploited during attacks.
- Malware and remote access tools linked to the group.
- Persistence mechanisms and suspicious registry modifications.
- Relevant MITRE ATT&CK techniques.

The investigation helped me practise connecting individual indicators and techniques to a broader adversary profile.

**[View investigation](Trooper-Unmasking-APT-X/)**

---

### 3. Finance Trail — Security Investigation

**Focus:** Incident investigation and forensic analysis  
**Tools:** Splunk, Sysmon, Suricata

A practical investigation involving suspicious activity in a financial environment.

The case study covers the use of security telemetry to reconstruct attacker activity, correlate events across different log sources, and establish an evidence-based timeline.

Particular attention was given to process execution, file creation, network activity, and the movement of data between systems.

**[View case study](finance-trail-case-study.md)**

---

## Tools and Technical Areas

| Area | Tools and techniques |
|---|---|
| SIEM and log analysis | Splunk, Elastic |
| Network monitoring | Zeek, Wireshark, Suricata |
| Endpoint investigation | Sysmon, Windows event logs |
| Threat intelligence | OpenCTI, MISP, MITRE ATT&CK |
| Operating systems | Linux, Windows |
| Scripting and investigation | Bash, SPL, Zeek scripting |
| Security operations | Incident triage, IOC analysis, event correlation, detection tuning |

These reflect tools and techniques I have worked with through practical exercises and technical training. My proficiency varies across them, and I continue to build experience through additional investigations.

## Investigation Approach

Although each case is different, I generally follow a similar process:

1. **Understand the scenario.** Identify the reported activity, available evidence, and questions that need answering.
2. **Establish a baseline.** Review normal activity and identify unusual connections, processes, authentication events, or file operations.
3. **Investigate the evidence.** Use relevant queries and tools to narrow down suspicious events.
4. **Correlate findings.** Compare timestamps, hosts, connection identifiers, and other indicators across available logs.
5. **Validate conclusions.** Check that findings are supported by the evidence and distinguish confirmed activity from assumptions.
6. **Document the investigation.** Record useful commands, findings, unsuccessful approaches, and lessons learned.

I also document commands that initially fail when the troubleshooting process offers something worth learning.

## About Me

I have a background in Information Technology, including IT support, systems administration, and information security.

My experience supporting users and troubleshooting technical issues has influenced how I approach security investigations: establish what happened, examine the available evidence, and work methodically towards an explanation.

I am currently building my practical experience in security operations, incident response, threat intelligence, and digital forensics through structured labs and independent study.

This repository will continue to grow as I complete and document additional investigations.

---

*The investigations in this repository were conducted in authorized training and lab environments. Findings relate to the supplied scenarios and datasets unless otherwise stated.*
