\# Threat Hunting with Zui



\## Project Overview



This investigation explores network threat hunting using Zui and Zeek logs in a simulated enterprise environment. The objective was to identify suspicious network activity through beaconing analysis, data exfiltration detection and lateral movement investigation.



\## Tools Used



\- Zui

\- Zeek

\- Zed Query Language

\- TryHackMe



\## Key Findings



| Investigation | Finding |

|---|---|

| C2 beaconing | 202 connections to a suspicious external IP |

| TLS analysis | update.softpatch-cdn.com |

| Outbound transfer | 5,348,854 bytes |

| Exfiltration artifact | backup\_archive.zip |

| SMB reconnaissance | 23 unanswered SYN attempts |

| Second-hop destination | 10.14.0.5 |



\## Skills Demonstrated



\- Hypothesis-driven threat hunting

\- Network traffic analysis

\- Query development and refinement

\- Protocol correlation

\- C2 beacon detection

\- Data exfiltration investigation

\- Lateral movement analysis

\- False positive assessment

\- Evidence documentation



\## Investigation Report



\[Read the full investigation report](./Zui\_SOC\_Threat\_Hunting\_Case\_Study.docx)



\## Lessons Learned



This investigation reinforced the importance of correlating multiple network log sources before reaching conclusions. It also demonstrated how iterative queries can help distinguish suspicious behaviour from legitimate network activity.



\## Disclaimer



This investigation was conducted in an authorised TryHackMe training environment. All findings relate to a simulated incident.

