# SOC Response Runbooks (synthetic)

> Synthetic knowledge base for demonstration only. Loaded into Foundry IQ as the
> grounding source for the Context agent. Each runbook is independently citable by
> its ID (e.g. `RB-004`). The Context agent retrieves the most relevant runbooks for
> an incident and returns them as citations.

---

## RB-001 — External reconnaissance / port scan
- **Keywords:** port scan, reconnaissance, SYN, internet scanner, Shodan, external probe
- **MITRE:** T1595 (Active Scanning)
- **Benign indicators:** source IP on the threat-intel allowlist; internet-wide research scanners; no follow-on connection succeeds.
- **Response:** Confirm the perimeter blocked the probe. If the source is an allowlisted scanner and nothing connected inbound, close as benign.
- **Recommended automation:** auto_resolve (low-risk, reversible: tag and close).

## RB-002 — Suspicious email attachment / phishing (initial access)
- **Keywords:** suspicious attachment, macro, xlsm, look-alike domain, SPF fail, DMARC none, phishing, initial access
- **MITRE:** T1566 (Phishing)
- **Benign indicators:** internal sender with DKIM/DMARC pass; known awareness-training campaign; links resolve to corporate intranet.
- **Malicious indicators:** newly registered look-alike sender domain; SPF=fail / DMARC=none; auto-open VBA macro; external delivery to a finance/AR user.
- **Response:** Detonate the attachment in a sandbox, pull the message from all mailboxes, capture the host for forensics, and check for child-process execution on the recipient endpoint. Treat as the possible first stage of an intrusion.
- **Recommended automation:** escalate_to_human (real mailbox purge / host isolation are impactful actions).

## RB-003 — Office application spawned a scripting engine (execution)
- **Keywords:** excel spawned powershell, office child process, encoded command, scripting engine, macro execution, dropped executable, APPDATA
- **MITRE:** T1059 (Command and Scripting Interpreter)
- **Benign indicators:** parent/child chain and script hash are on the approved-automation allowlist (e.g. SCCM/ccmexec running signed deployment scripts); service account context.
- **Malicious indicators:** Office app (excel/word) spawning powershell with an encoded command; payload downloaded from an external IP; executable written to %APPDATA%; no matching approved automation.
- **Response:** Correlate with the delivery vector (RB-002) and any follow-on credential activity. Collect the dropped artifact hash. Escalate if no approved automation matches.
- **Recommended automation:** escalate_to_human when unmatched; auto_resolve only when the chain matches an approved-automation allowlist entry.

## RB-004 — Credential store access (credential dumping)
- **Keywords:** LSASS, credential dumping, credential access, memory read handle, secrets, mimikatz-like
- **MITRE:** T1003 (OS Credential Dumping)
- **Benign indicators:** access by an allowlisted EDR/AV or backup process with signed binary.
- **Malicious indicators:** handle to lsass.exe opened by a recently dropped/unsigned artifact; follows execution activity on the same host.
- **Response:** Treat as high-severity active intrusion. Preserve memory, identify which credentials were resident, and assume any cached privileged accounts are compromised. Prepare to rotate exposed credentials (human-approved).
- **Recommended automation:** escalate_to_human (credential rotation and host isolation are impactful).

## RB-005 — Internal lateral movement (SMB/RDP)
- **Keywords:** lateral movement, SMB, RDP, remote session, sqladmin, new admin login, never logged in before
- **MITRE:** T1021 (Remote Services)
- **Benign indicators:** session by an account that routinely administers the target from that source; matches a scheduled maintenance window.
- **Malicious indicators:** privileged account (e.g. sqladmin) connecting from a user workstation for the first time; session begins seconds after credential-access activity on the source host.
- **Response:** Map the movement path, identify the target's business criticality, and contain the source and target (human-approved isolation). Hunt for additional sessions using the same credential.
- **Recommended automation:** escalate_to_human (host isolation / account disable are impactful).

## RB-006 — Data exfiltration / large outbound transfer
- **Keywords:** exfiltration, large outbound transfer, DLP, data upload, uncommon port, egress above baseline, compressed archive
- **MITRE:** T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol)
- **Benign indicators:** scheduled backup/replication job to a known destination; transfer volume within the asset's documented baseline.
- **Malicious indicators:** large compressed archive to an external IP over an uncommon port; egress far above the asset's baseline; transfer tied to a suspicious privileged session.
- **Response:** Treat as confirmed data breach pending validation. Capture the destination IOC, block egress (human-approved), preserve the session, and engage incident response and legal/notification workflows for restricted data.
- **Recommended automation:** escalate_to_human (egress blocking and breach handling are impactful).

## RB-007 — Potentially unwanted program / tracking cookie auto-cleaned
- **Keywords:** tracking cookie, PUP, adware, antivirus removed, low-risk, scheduled scan
- **MITRE:** N/A
- **Benign indicators:** AV auto-removed a low-risk cookie/PUP; no executable; scheduled scan.
- **Response:** No action required; the AV already remediated.
- **Recommended automation:** auto_resolve (benign).

## RB-008 — Account management (password reset / provisioning)
- **Keywords:** password reset, account management, helpdesk ticket, service desk, provisioning, verified callback
- **MITRE:** N/A
- **Benign indicators:** action tied to a verified helpdesk ticket with identity verification (callback).
- **Malicious indicators:** reset with no matching ticket, or self-service reset immediately followed by anomalous sign-ins.
- **Response:** Confirm the change maps to a verified ticket. If yes, close as benign.
- **Recommended automation:** auto_resolve when a verified ticket exists.

## RB-009 — Authentication anomalies (failed logins / impossible travel)
- **Keywords:** failed sign-ins, brute force, impossible travel, roaming, service account, lockout, identity protection
- **MITRE:** T1110 (Brute Force), T1078 (Valid Accounts)
- **Benign indicators:** failed logins from a service account with a stale/rotated password in its job config (no success, no lockout, recurring); impossible-travel auto-dismissed as carrier roaming on the same compliant device.
- **Malicious indicators:** failed logins followed by a success from a new location; impossible travel with a new/unmanaged device.
- **Response:** Check whether the pattern matches a known service-account misconfiguration or benign roaming. Escalate only if a successful anomalous sign-in follows.
- **Recommended automation:** auto_resolve when benign pattern confirmed.

## RB-010 — Security hygiene / approved misconfiguration
- **Keywords:** certificate expiring, TLS expiry, public storage, public read, misconfiguration, change approved, exception, USB enrolled, newly registered domain approved
- **MITRE:** N/A
- **Benign indicators:** informational hygiene finding; configuration covered by an approved change (CHG-####); enrolled/encrypted device; vendor domain approved via change control.
- **Response:** Route to the owning team as a tracked hygiene item. No incident.
- **Recommended automation:** auto_resolve (informational).
