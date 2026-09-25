# Playbook: suspected LSASS credential dumping (T1003.001)

**Trigger:** alert from `proc_creation_win_rundll32_comsvcs_minidump` or `proc_access_win_lsass_suspicious_access`, or a hunt hit from H3.
**Severity:** treat as high until disproved. Successful LSASS dumping usually means credentials, not just one host, are at risk.

## 1. Triage (first 15 minutes)
- Is the process chain expected? Record image, parent, command line, user and hashes.
- Was it a known security tool or an authorised test? Check the change calendar and the red team contact.
- Which account ran it, and what privileges does that account have?
- What else ran on the host in the 30 minutes before the alert (initial access, downloads, persistence)?
- Decide: **true positive**, **benign true positive** (authorised), or **false positive**. Write down the reasoning.

## 2. Scope
- Search the fleet for the same command line, the same parent process, and other LSASS access events.
- Find every account with an interactive or network logon on the host around the dump time. All of them are exposed.
- Check for lateral movement from this host (SMB admin shares, remote services, new logons using the exposed accounts).

## 3. Contain
- Isolate the host at the network level; keep it powered on so memory can be captured.
- Disable or force-reset the exposed accounts. For privileged or service accounts, coordinate with the owners first.
- Block any identified attacker infrastructure (domains, IPs) at the proxy and firewall.

## 4. Preserve evidence
- Capture memory, then collect the dump file, relevant event logs (Sysmon, Security, PowerShell) and the scheduled tasks and Run keys.
- Hash every collected artifact and record who collected it and when (chain of custody).

## 5. Eradicate
- Remove persistence found during scoping (Run keys, scheduled tasks, services) after exporting it as evidence.
- Rebuild the host from a known-good image if compromise of the OS cannot be excluded.
- Rotate the credentials, tickets and secrets that were present on the host, including Kerberos (krbtgt) if domain-level exposure is suspected.

## 6. Recover
- Return the host to service only after a clean rebuild and monitoring is confirmed.
- Watch the exposed accounts for anomalous logons for at least 2 weeks.

## 7. Lessons learned
- Did the rule fire, and how quickly? Record time to detect and time to contain.
- What was missed and needs a new rule or hunt? Add it under `detections/` or `hunts/`.
- Update this playbook and the `falsepositives` notes of the rules involved.

## References
- MITRE ATT&CK T1003.001 - https://attack.mitre.org/techniques/T1003/001/
- NIST SP 800-61 - https://csrc.nist.gov/pubs/sp/800/61/r2/final
