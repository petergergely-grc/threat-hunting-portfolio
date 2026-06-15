# 🛡️ Threat Hunt — Ghost in the Stack

> **Incident:** GF-INC-2026-0517 | **Severity:** High — Active Compromise  
> **Analyst:** Peter Gergely (T2) | **Platform:** Microsoft Sentinel / Defender XDR  
> **Environment:** Greenfield Estate | **Workspace:** LAW-SilentCorridor

---

## 📌 Executive Summary

On the night of April 30–May 1, 2026, a sophisticated threat actor gained a foothold on a Linux developer host inside the Greenfield estate. What began as a single suspicious process quietly downloading a file from attacker-controlled infrastructure escalated into a multi-stage intrusion involving credential harvesting, SSH backdooring, systemd-level persistence, and a determined — but ultimately failed — attempt to pivot into the Windows environment.

The investigation was handed off from Tier-1 at 02:30 UTC with 17 correlated alerts and no clear picture of how the attack started, how far it had spread, or whether it was still active. By end of shift, all three questions had been answered — and the implant was confirmed still live on the compromised host.

---

## 🎯 What I Was Asked to Do

- Reconstruct the full attack timeline from first contact to end of investigation window
- Identify every compromised account, tool, and attacker-controlled artefact
- Map all observed behaviours to MITRE ATT&CK and assess detection coverage
- Determine whether lateral movement into the Windows estate succeeded
- Provide actionable containment and detection gap recommendations

---

## 🖥️ Environment

| Field | Detail |
|---|---|
| Incident ID | GF-INC-2026-0517 |
| SIEM | Microsoft Sentinel / Defender XDR |
| Log Workspace | LAW-SilentCorridor |
| Investigation Window | 2026-04-30 21:00 → 2026-05-01 04:00 UTC |
| Primary Host Compromised | GF-DEV01 (Ubuntu Developer Host) |
| Accounts Involved | a.kumar, sancadmin, t.harris |
| Telemetry Sources | MDE Linux EDR, Microsoft Sentinel, MDC Agentless |

---

## 📖 The Attack Story

### Chapter 1 — The Quiet Entry (21:54 UTC)

At 21:54 UTC, a single curl command executed on the Ubuntu developer host GF-DEV01 under the account `a.kumar`. The command reached out to `https://sync.abordsecurity.space/` — a domain fronted by Cloudflare's CDN — and downloaded a binary named `helix-update` into `/tmp/`. The file was made executable and launched within seconds.

The use of Cloudflare as front-end infrastructure was deliberate: blocking the IP at the perimeter would have disrupted access to millions of legitimate websites sharing the same CDN. The only reliable detection surface was the host itself.

**MITRE:** T1105 – Ingress Tool Transfer | T1078 – Valid Accounts

---

### Chapter 2 — Going Dark (21:54–22:05 UTC)

Immediately after execution, the operator used `nohup` to detach the implant from the terminal. When the shell exited, the Linux kernel re-parented the orphaned process to PID 1 (init/systemd) — making it visually indistinguishable from a native system daemon in any process tree view.

The implant (`helix-update`, PID 34616, PPID 1) established encrypted C2 communications back to attacker infrastructure over HTTPS via Cloudflare, using the Ligolo reverse proxy framework. It remained running in this state for the entire investigation window.

**MITRE:** T1059.004 – Unix Shell | T1036/T1574 – Defense Evasion | T1572 – Protocol Tunneling

---

### Chapter 3 — Harvesting the Keys to the Kingdom (22:05–22:57 UTC)

With C2 established, the implant began systematic credential harvesting — not through noisy dump utilities, but through legitimate system binaries used as living-off-the-land proxies. Short-lived child processes (`aws`, `kubectl`, `ssh`, `bash`) were spawned to access specific credential stores monitored by Linux auditd watch rules:

- `aws_creds` — AWS credentials granting potential cloud infrastructure access
- `ssh_user_keys` — SSH private keys enabling further lateral movement
- `kube_creds` — Kubernetes configuration exposing container orchestration access

The implant also directly read files under the `claude_data` watch key — six access events — suggesting targeted collection of sensitive developer environment data.

**MITRE:** T1552.001 – Credentials in Files | T1552.004 – Private Keys | T1005 – Data from Local System

---

### Chapter 4 — Leaving a Back Door (22:57 UTC)

At 22:57 UTC, the implant appended an SSH public key to `/home/a.kumar/.ssh/authorized_keys`. The key carried the comment `octotempest@operator` — an operator attribution marker linking the activity to the Scattered Spider / Octo Tempest threat cluster.

This backdoor would survive a full password reset of the `a.kumar` account unless the `authorized_keys` file was explicitly cleaned.

**MITRE:** T1098.004 – SSH Authorized Keys

---

### Chapter 5 — The Second Operator (23:39 UTC)

At 23:39 UTC, a new interactive SSH session appeared on GF-DEV01 — this time under `sancadmin`, a privileged administrator account — originating from external IP `194.36.110.139` (AS9009, M247 London infrastructure). Notably, a helpdesk ticket queued before this incident had flagged `sancadmin` credentials for routine rotation — suggesting the attacker may have obtained them prior to this session.

The `sancadmin` session immediately began staging a second toolset: a second Ligolo implant (`helix-sync`), a Windows executable (`hbsync.exe`), and a Python WMI attack script (`wmi_exec.py`). These were transferred silently via SFTP before any interactive shell commands appeared in the log.

**MITRE:** T1078 – Valid Accounts | T1105 – Ingress Tool Transfer

---

### Chapter 6 — Digging In (23:39–00:09 UTC)

Before attempting lateral movement, `sancadmin` established durable persistence on DEV01 via systemd:

```bash
sudo cp /tmp/helix-sync /usr/local/bin/helix-sync
sudo tee /etc/systemd/system/helix-sync.service
sudo systemctl enable helix-sync
```

Even if GF-DEV01 was rebooted, the implant would restart automatically. Combined with the SSH backdoor, the attacker now had two independent persistence mechanisms across different system layers.

**MITRE:** T1543.002 – Create or Modify System Process: Systemd Service

---

### Chapter 7 — The Pivot That Wasn't (00:09–00:21 UTC)

With persistence secured, `sancadmin` turned to lateral movement — attempting to cross from the Linux host into the Windows estate via three protocols in sequence:

| Protocol | Tool | Target | Result |
|---|---|---|---|
| SMB | `smbclient` | GF-WS01 C$ | Failed — access denied |
| WinRM | `pwsh Invoke-Command` | 10.1.0.133:5985 | Failed — rc=1 |
| WMI | `wmi_exec.py` | Windows targets | Not confirmed |

The most technically sophisticated attempt came at 00:18 UTC: a double base64-encoded PowerShell payload delivered via WinRM, designed to download `hbsync.exe` from the Cloudflare-fronted C2 to `$env:TEMP\hbsync.exe` on GF-WS01, using stolen `t.harris` domain credentials (`Summer2025!`). The WinRM connection failed — the payload was never delivered.

**MITRE:** T1021.002 – SMB | T1021.006 – WinRM | T1059.001 – PowerShell | T1140 – Deobfuscation

---

### Chapter 8 — What Was Left Behind

At end of shift, three active artefacts remained on GF-DEV01 in distinct system layers:

| Artefact | Location | State |
|---|---|---|
| `helix-update` | `/tmp/helix-update` | **Running** — PID 34616, PPID 1, live since 21:54 UTC |
| `helix-sync` | `/etc/systemd/system/helix-sync.service` | **Dormant** — registered, not confirmed running |
| SSH backdoor key | `/home/a.kumar/.ssh/authorized_keys` | **Persistent** — survives reboots and password resets |

This was not a historical incident. The implant was live at handoff — requiring immediate IR engagement before any remediation.

---

## 🧬 MITRE ATT&CK Coverage

| Phase | Technique | ID | Priority |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | 🔴 Critical |
| Execution | Ingress Tool Transfer | T1105 | 🔴 Critical |
| Execution | Unix Shell | T1059.004 | 🔴 Critical |
| Defense Evasion | Process Reparenting (PPID=1) | T1036/T1574 | 🔴 Critical |
| C2 | HTTPS via Cloudflare CDN | T1071.001 | 🔴 Critical |
| C2 | Protocol Tunneling (Ligolo) | T1572 | 🟠 High |
| Credential Access | Credentials in Files | T1552.001 | 🔴 Critical |
| Credential Access | Private Keys | T1552.004 | 🔴 Critical |
| Persistence | SSH Authorized Keys | T1098.004 | 🔴 Critical |
| Persistence | Systemd Service | T1543.002 | 🔴 Critical |
| Lateral Movement | SMB Admin Shares | T1021.002 | 🟠 High |
| Lateral Movement | WinRM | T1021.006 | 🟠 High |
| Lateral Movement | WMI | T1047 | 🟠 High |
| Execution | PowerShell | T1059.001 | 🔴 Critical |
| Defense Evasion | Double-encoded Payload | T1140 | 🟠 High |

---

## 🚨 Key Detection Gaps Identified

- **No alerting on `nohup`-based process daemonisation** — PPID=1 for non-system binaries should trigger an alert
- **No detection on outbound `curl` to newly-registered domains** — DNS reputation monitoring would have caught this at download time
- **Cloudflare CDN masking C2 infrastructure** — IP blocking is ineffective; detection must shift to domain-level (DNS/TLS SNI) and behaviour-level (process trees)
- **Auditd watch keys produced telemetry but no correlated alert** — the `aws_creds`, `ssh_user_keys`, and `kube_creds` hits were queryable in Sentinel but never alerted in real time
- **`sancadmin` interactive shell session not flagged** — privileged service accounts opening interactive shells and downloading binaries should be a high-priority anomaly
- **Double-encoded PowerShell not caught by ScriptBlock correlation** — automated depth-two decoding in SIEM would surface true payload intent at detection time

---

## 🧾 Final Assessment

> **Threat Actor Sophistication:** High  
> **Current Threat Status:** Active — live implant on GF-DEV01  
> **Lateral Movement:** Failed — Windows estate not compromised  
> **Recommended Action:** Immediate isolation of GF-DEV01, credential rotation for all affected accounts (a.kumar, sancadmin, t.harris), full forensic triage of GF-WS01

The attacker demonstrated clear operational tradecraft: Cloudflare CDN obfuscation, process reparenting for evasion, living-off-the-land credential harvesting, layered persistence, and domain account abuse for lateral movement. The lateral movement phase failed — likely due to network segmentation — which was the primary containment that prevented broader estate compromise.

However, with an active C2 implant, an SSH backdoor, and compromised domain credentials still in the environment at end of shift, this threat was far from contained at handoff.

---

## 🛠️ Tools & Skills Demonstrated

- **Microsoft Sentinel** — KQL threat hunting across 13 custom log tables
- **Defender XDR** — Alert triage, T1 re-validation, incident correlation
- **MITRE ATT&CK v15** — Full technique mapping across all attack phases
- **Linux forensics** — Process trees, auditd watch rules, shell history analysis
- **Threat intelligence** — ASN enrichment, IOC identification, actor profiling
- **Incident response** — NIST 800-61 lifecycle, containment prioritisation

---

## 📎 Supporting Documentation

- [Technical Annex — KQL Queries & Flag Evidence](./technical-annex.md)

---

*Completed as part of the Josh Madakor Cyber Range internship program | Workspace: LAW-SilentCorridor*  
*Analyst: Peter Gergely | [LinkedIn](https://www.linkedin.com/in/peter-g-03846161/) | [GitHub](https://github.com/petergergely-grc)*
