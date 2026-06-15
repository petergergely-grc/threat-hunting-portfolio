# 🛡️ Threat Hunt — Signals After the Noise (Azure VM Intrusion)

> **Incident:** INC-2025-1213-PHTG | **Severity:** Critical — Active Compromise  
> **Analyst:** Peter Gergely (T2) | **Platform:** Microsoft Sentinel / Defender XDR  
> **Environment:** Azure VM Estate | **Workspace:** LAW-Cyber-Range  
> **Flags Captured:** 28 of 29 (Q00–Q29)

---

## 📌 Executive Summary

On December 13, 2025, a threat operator with pre-obtained credentials gained access to two Azure Windows VMs via RDP, deployed a fully masqueraded tooling workspace, established dual C2 channels, tampered with Windows Defender, dumped credentials from LSASS on both hosts, and left behind redundant persistence mechanisms — all while mimicking the appearance of routine cloud administration activity.

The investigation window ran from 09:00 to 18:00 UTC. By end of shift, the blast radius was confirmed as two hosts, lateral movement was contained, and the full attack chain had been reconstructed from Azure control-plane telemetry through in-guest EDR evidence.

---

## 🎯 What I Was Asked to Do

- Determine whether initial access was brute force or credential reuse and prove it from telemetry
- Reconstruct the full attack chain from Azure Portal sign-in through LSASS credential dumping
- Identify all persistence mechanisms and validate whether they functioned
- Map Defender tampering — what was excluded, how, and what survived
- Confirm the blast radius and determine whether lateral movement continued beyond the two known hosts

---

## 🖥️ Environment

| Field | Detail |
|---|---|
| Incident ID | INC-2025-1213-PHTG |
| SIEM | Microsoft Sentinel / Defender XDR (MDE) |
| Investigation Window | 2025-12-13 09:00 → 18:00 UTC |
| Primary Host | azwks-phtg-02 (10.0.0.152) — initial access target |
| Secondary Host | azwks-phtg-01 (10.0.0.105) — lateral movement target |
| Attacker IP | 173.244.55.131 |
| Compromised Account | vmadminusername (local admin on both VMs) |

---

## 📖 The Attack Story

### Chapter 1 — Control Plane Before Console (09:02–09:31 UTC)

The attack didn't begin with a login attempt. It began with the Azure Portal.

At 09:02 UTC, an Entra identity (`98eb2485...@lognpacific.com`) authenticated to Azure from `173.244.55.131`. This identity held the **Virtual Machine Contributor** RBAC role — enough to manage VMs without touching the guest OS. Over the next 29 minutes, the operator used the Azure control plane to reset the `vmadminusername` password via the VMAccess extension, then restarted `azwks-phtg-02` to apply the new credentials.

At 09:31, the same IP address authenticated via RDP to the now-restarted VM with the freshly reset password. This was not brute force — the operator already controlled the credential before a single RDP packet was sent.

**MITRE:** T1078 – Valid Accounts | T1098 – Account Manipulation (VMAccess)

---

### Chapter 2 — Lateral Movement (09:48 UTC)

Within 17 minutes of establishing a foothold on `azwks-phtg-02`, the operator pivoted to `azwks-phtg-01` via RDP using the same `vmadminusername` account from the internal IP `10.0.0.152`. The logon sequence — Network logon followed immediately by RemoteInteractive — confirmed hands-on-keyboard access to the second host.

No further lateral movement occurred. Zero logon events were recorded from `10.0.0.105` to any other host in the fleet during the entire investigation window. Blast radius: two hosts only.

**MITRE:** T1021.001 – Remote Desktop Protocol

---

### Chapter 3 — Deploying the Workspace (10:11–10:13 UTC)

The operator launched their orchestrator script — `_.ps1` from `C:\Users\vmAdminUsername\Documents\PHTG\` — with `-WindowStyle Hidden -ExecutionPolicy Bypass`, suppressing any visible window and bypassing execution policy restrictions. This script bootstrapped the operator's full tooling workspace under:

```
C:\ProgramData\PHTG\HealthCloud\
├── Cache\       ← 22 task scripts (task_FLAG-01 through FLAG-22)
├── Bin\         ← HealthCloudTray.ps1, amsi_probe.ps1, hc_lineage.ps1
└── TempCache\   ← staging artifacts
```

The name **HealthCloud** was deliberate — designed to look like legitimate cloud health-monitoring software. Every component of the operator's toolkit carried this branding: folder names, binary names, registry keys, C2 domains, and event log sources.

Files in the Cache and TempCache directories were hidden using `attrib +h +s` — 17 files in Cache and 2 in TempCache — making them invisible in Windows Explorer and standard directory listings.

**MITRE:** T1036.005 – Masquerading | T1564.001 – Hidden Files and Directories

---

### Chapter 4 — The Masqueraded LOLBin (10:12 UTC)

The operator's primary execution engine was `PHTGHealthCloudSvc.exe` — a renamed copy of `bitsadmin.exe`. The version info embedded in the binary (`ProcessVersionInfoOriginalFileName`) exposed the masquerade: the file claimed to be a HealthCloud service component but was actually a Windows built-in tool repurposed for C2 activity.

It executed 22 times on the secondary host alone, each time with campaign-specific parameters:

```
PHTGHealthCloudSvc.exe /healthcheck /flag:FLAG-XX /device:azwks-phtg-01 /role:workstation
```

This loop maintained a persistent heartbeat on the operator's infrastructure while appearing as a routine service healthcheck to any observer.

**MITRE:** T1036.005 – Masquerading | T1218 – System Binary Proxy Execution

---

### Chapter 5 — Persistence (10:12–10:13 UTC)

The operator deployed three complementary persistence mechanisms:

**1. HKCU Run Key** — `PHTGHealthCloudTray` written to `HKEY_CURRENT_USER\...\CurrentVersion\Run`, launching `HealthCloudTray.ps1` silently at every user logon. Confirmed functional — fired twice during the observation window.

**2. Startup Folder Shortcut** — `PHTG HealthCloud.lnk` dropped in the Windows Startup folder. Windows Defender detected it and generated two AntivirusReport events — but did not block or remove it. The persistence survived detection.

**3. Custom Event Log Source** — `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud` registered, enabling the operator's tooling to write entries to the Application event log under a legitimate-looking source name, hiding operational telemetry in plain sight.

**MITRE:** T1547.001 – Registry Run Keys / Startup Folder | T1112 – Modify Registry

---

### Chapter 6 — Defender Tampering (11:11–11:14 UTC)

Rather than disabling Defender entirely — which would trigger a high-severity alert — the operator used `Add-MpPreference` to surgically exclude only their own tooling:

- **Path exclusion:** `C:\ProgramData\PHTG\HealthCloud\Cache` — blinded Defender to all 22 staged task scripts
- **Process exclusion:** `PHTGHealthCloudSvc.exe` — prevented Defender from inspecting the masqueraded LOLBin during execution
- **Temporary exclusion:** `C:\Users\vmAdminUsername\Documents\PHTG` — added before launching `_.ps1`, removed immediately after. No permanent trace.

The operator also ran `amsi_probe.ps1` to check whether AMSI was active before deploying primary payloads — a standard pre-deployment reconnaissance step in offensive tradecraft.

**MITRE:** T1562.001 – Impair Defenses: Disable or Modify Tools

---

### Chapter 7 — Dual C2 Channels (11:12–11:13 UTC)

Two independent C2 channels operated simultaneously:

**Channel 1 — Tool retrieval:** Outbound connections to `updates.health-cloud.cc` for payload staging (T1105)

**Channel 2 — Beacon check-in:** Base64-encoded PowerShell beacons to `status.health-cloud.cc/api/checkin` and `/api/status` (T1071.001)

The dual-channel design provided redundancy — if one channel was blocked, the other maintained access. It also split the traffic signature across two distinct mechanisms, making correlation harder for defenders working each stream in isolation.

The operator also used `cmd.exe /c` as an intermediary to launch `hc_lineage.ps1` and `phtg_health_diag_update_FLAG-22.bat`, deliberately breaking the process lineage tree to obscure the parent-child relationship between their orchestrator script and downstream payloads.

**MITRE:** T1071.001 – Web Protocols | T1105 – Ingress Tool Transfer | T1027 – Obfuscated Files | T1059.003 – Windows Command Shell

---

### Chapter 8 — LSASS Credential Dumping (10:38 & 11:14 UTC)

The operator's `task_FLAG-13.ps1` executed a two-stage credential access sequence on both hosts:

1. **Query handle** — opened LSASS with `DesiredAccess: 5136` (0x1410) to verify accessibility
2. **Full access handle** — escalated to `DesiredAccess: 2047999` (0x1FFFFF = `PROCESS_ALL_ACCESS`) within one second
3. **Memory read** — `ReadProcessMemoryApiCall` confirmed active extraction of credential material from LSASS memory

The escalation from query to full access is the high-fidelity indicator — a legitimate process querying LSASS for metadata stops at the query handle. The one-second escalation to PROCESS_ALL_ACCESS reveals intent, and `ReadProcessMemoryApiCall` confirms execution. Any credentials cached in memory on both hosts at the time of the dump should be considered fully compromised.

**MITRE:** T1003.001 – OS Credential Dumping: LSASS Memory

---

## 🧬 MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Valid Accounts | T1078 |
| Execution | PowerShell | T1059.001 |
| Execution | Windows Command Shell | T1059.003 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | Masquerading | T1036.005 |
| Defense Evasion | Hidden Files and Directories | T1564.001 |
| Defense Evasion | Modify Registry | T1112 |
| Defense Evasion | Impair Defenses | T1562.001 |
| Defense Evasion | Obfuscated Files | T1027 |
| Credential Access | LSASS Memory | T1003.001 |
| Lateral Movement | Remote Desktop Protocol | T1021.001 |
| Command & Control | Web Protocols | T1071.001 |
| Command & Control | Ingress Tool Transfer | T1105 |

---

## 🚨 Key Findings

- **Root cause:** Over-privileged Azure RBAC (VM Contributor) combined with no MFA on RDP allowed the operator to reset credentials via the control plane and walk straight in
- **Blast radius:** Two Azure Windows VMs — no further lateral movement confirmed
- **Persistence:** Two mechanisms confirmed functional (Run key fired twice); Startup shortcut survived Defender detection without remediation
- **Credential exposure:** LSASS dumped on both hosts — all cached credentials must be treated as compromised
- **Defender:** Partially blinded via surgical exclusions — coverage degraded specifically for operator tooling, intact for everything else

---

## 🛠️ Tools & Skills Demonstrated

- **Microsoft Sentinel / MDE** — KQL hunting across DeviceProcessEvents, DeviceRegistryEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceEvents, AzureActivity, BehaviorAnalytics
- **Azure control-plane analysis** — AzureActivity log correlation, RBAC abuse identification, VMAccess extension forensics
- **MITRE ATT&CK v15** — Full technique mapping across all attack phases
- **LOLBin detection** — ProcessVersionInfoOriginalFileName mismatch analysis
- **Credential access forensics** — OpenProcessApiCall / ReadProcessMemoryApiCall chain reconstruction
- **Defender telemetry analysis** — MpPreference exclusion tracking, AntivirusReport interpretation

---

## 📎 Supporting Documentation

- [Technical Annex — KQL Queries & Flag Evidence](./technical-annex.md)

---

*Completed as part of the Josh Madakor Cyber Range internship program | Workspace: LAW-Cyber-Range*  
*Analyst: Peter Gergely | [LinkedIn](https://www.linkedin.com/in/peter-g-03846161/) | [GitHub](https://github.com/petergergely-grc)*
