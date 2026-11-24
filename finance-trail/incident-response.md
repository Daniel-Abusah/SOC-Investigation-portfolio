# Recommended incident response

The following actions are hypothetical recommendations for a comparable production incident. They were not performed during this lab.

1. Triage and scope: validate the affected workstation, user, process lineage, scheduled task and related network activity.
2. Containment: coordinate isolation of the affected endpoint and restrict validated malicious destinations while considering business impact.
3. Preserve evidence: collect relevant endpoint, mail, network and file server logs; preserve suspicious files safely with hashes and collection records.
4. Hunt: search other endpoints for validated indicators and related behaviours; inspect the destination share for the staged archive.
5. Eradication: remove confirmed malicious tasks and binaries after evidence preservation and address the initial access weakness.
6. Recovery: restore a trusted system state, validate normal operation and monitor for recurrence.
7. Impact assessment: establish archive contents, access scope and any onward transfer. Do not assume external exfiltration from an internal SMB write.
8. Lessons learned: review phishing controls, endpoint visibility, task auditing and network monitoring.
