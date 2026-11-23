# Trooper — Unmasking APT X

> Cyber Threat Intelligence lab case study | OpenCTI • MITRE ATT&CK • TryHackMe

**Scope:** Training environment. The case study records evidence from the exercise, not an independently investigated production compromise.

## Findings at a glance

| Finding | Result | Mapping | Evidence status |
|---|---|---|---|
| Initial access | Spearphishing Attachment | T1566.001 | Screenshot verified |
| Malware | USBferry | — | Screenshot verified |
| Actor | Tropic Trooper (APT23) | — | Lab attribution |
| Attack patterns | 40 | — | Screenshot verified |
| Exchange RCE | CVE-2021-34473 | — | Screenshot + accepted |
| Tool | BITSAdmin | T1197 (related) | Screenshot verified |
| Remote access | PoisonIvy | — | Candidate; acceptance not shown |
| Persistence | HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell | T1547.004 | Screenshot verified |
| Concealment | JPG | T1027.003 | Screenshot verified |

## Executive summary

This case study documents a guided OpenCTI investigation of a fictionally named threat actor, APT X, in the TryHackMe Trooper exercise. The investigation linked the scenario to Tropic Trooper and examined its malware, techniques, exploited vulnerabilities, and persistence behavior. Findings reflect the exercise dataset and screenshots reviewed during the lab; they do not establish a new real-world incident.

## Scenario and objectives

A multinational technology organization reportedly experienced intellectual-property theft and operational disruption. The analyst was tasked with using OpenCTI relationships and ATT&CK-aligned intelligence to identify the actor, initial-access method, malware, remote-access capability, vulnerability exploitation, persistence, and concealment behavior.

## Lab environment and methodology

Platform: TryHackMe Trooper lab and OpenCTI. Workflow: search the APT X report and threat actor; inspect report entities; pivot to USBferry; review malware relationships to identify the intrusion set; examine the intrusion set’s relationship distribution and knowledge list; inspect technique descriptions for precise artifacts. Counts are specific to the lab dataset.

## Finding 1 — Initial access

APT X report → Entities displayed [T1566.001] Spearphishing Attachment. This technique is part of the Initial Access tactic. Evidence: screenshot of the report entity list and attack pattern overview.

## Finding 2 — Malware and actor attribution

Filtering the relevant knowledge relationships to Malware returned USBferry. A separate USBferry profile exposed a Standard STIX ID beginning malware--5d0ea014-1ce9-5d5c-bcc7-f625a079…; the complete ID was not preserved in the conversation and is intentionally not invented here. The lab investigation associated USBferry with Tropic Trooper (APT23). Attribution is a lab-supported association, not independent proof of responsibility for the fictional incident.

## Finding 3 — Attack pattern count

Tropic Trooper’s OpenCTI Overview → Distribution of Relations displayed 40 Attack Pattern relationships, alongside 5 Malware, 4 Vulnerability, 1 Threat Actor Group, and 1 Tool. These are relationship counts, not necessarily unique real-world behaviors.

## Finding 4 — Exchange exploitation

The vulnerability timeline included CVE-2021-34473, a Microsoft Exchange Server remote code execution vulnerability associated with the ProxyShell chain. The same timeline showed CVE-2021-34523 (privilege escalation), CVE-2021-31207 (security feature bypass), and CVE-2023-26360 (Adobe ColdFusion). The TryHackMe answer CVE-2021-34473 was accepted.

## Finding 5 — Command-line utility

The single tool relationship led to BITSAdmin, a Windows command-line utility for creating and managing Background Intelligent Transfer Service jobs. Legitimate administration functionality can be abused for malicious transfers or job-based execution. The lab evidence confirms the tool association, not a specific observed BITSAdmin command.

## Finding 6 — Remote access malware

The five associated malware names were YAHOYAH, USBferry, ShadowPad, PoisonIvy, and KeyBoy. PoisonIvy was identified in the walkthrough as the remote access trojan candidate. The conversation does not include an explicit TryHackMe acceptance confirmation for this particular answer; treat it as provisionally identified pending confirmation.

## Finding 7 — Registry persistence

The OpenCTI knowledge list under Persistence showed T1547.004 (Winlogon Helper DLL) with a description stating that Tropic Trooper created HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell and set its value to establish persistence. This exact registry path was visible in the screenshot.

## Finding 8 — Concealment via image files

The Stealth section showed T1027.003 (Steganography), describing JPG files containing encrypted payloads used to conceal backdoor routines and evade detection. The format answer was JPG. The list also included T1140 (Deobfuscate/Decode Files or Information), describing decryption of image-contained payloads.

## Analyst interpretation

The documented behaviors form a plausible espionage-oriented sequence: targeted phishing and exploitation for access; backdoors and remote-access tooling for control; registry modification for persistence; and encoded or image-concealed payloads to complicate detection. This is a synthesis of separate intelligence relationships, not a verified chronological chain from one incident.

## Detection and defensive considerations

Monitor Office-to-script execution chains and suspicious attachment handling; prioritize remediation of exposed Exchange vulnerabilities; review BITS job creation and unusual transfers; audit changes to Winlogon\Shell registry values; investigate unexpected DLL loading and image files carrying non-image payloads. Correlate with process, registry, network, and endpoint telemetry before escalating.

## Limitations and evidence quality

The original scenario is a training exercise. Most facts were read from screenshots of the OpenCTI instance. The full USBferry STIX ID was not captured; no hashes, domains, timestamps of actual compromise, or incident logs were supplied. The remote-access answer PoisonIvy was not explicitly confirmed as accepted. Avoid presenting these omissions as verified facts.

## Lessons learned

OpenCTI’s report Entities tab and intrusion-set Knowledge tab serve different investigative purposes. Entity-type filtering reduces irrelevant results. Relationship descriptions often contain the exact artifacts needed for attribution and detection. MITRE IDs are useful context, but the narrative and direct evidence should drive conclusions.

## Screenshot checklist

01 — APT X report Entities: T1566.001; 02 — Malware relationship: USBferry; 03 — USBferry Standard STIX ID (capture full value if available); 04 — Tropic Trooper relationship distribution; 05 — Exchange vulnerability timeline; 06 — BITSAdmin description; 07 — Five malware names; 08 — Winlogon\Shell persistence relationship; 09 — JPG steganography relationship. Add images to a screenshots/ directory and link them from the README.

## Suggested repository layout

```text
trooper-unmasking-apt-x/
├── README.md
├── screenshots/
│   └── (add your redacted OpenCTI screenshots here)
└── report/
    └── Trooper_Unmasking_APT_X_CTI_Report.docx
```

## References

- MITRE ATT&CK: https://attack.mitre.org/
- MITRE ATT&CK T1566.001: https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1547.004: https://attack.mitre.org/techniques/T1547/004/
- MITRE ATT&CK T1027.003: https://attack.mitre.org/techniques/T1027/003/
- Microsoft Security Response Center: https://msrc.microsoft.com/
- TryHackMe Trooper exercise (lab instance; access may require enrollment).
