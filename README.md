# SOC Home Lab

Home lab built to practice detection engineering. Splunk SIEM on a Windows VM, logs forwarded from Windows + Kali, attacks simulated with Atomic Red Team.

**Stack:** Splunk Enterprise · Sysmon (SwiftOnSecurity config) · Atomic Red Team · Hydra · Nmap · VirtualBox

| VM | OS | IP | Role |
|---|---|---|---|
| Windows | Windows 11 | 192.168.56.128 | Splunk + target |
| Kali | Kali Linux | 192.168.56.129 | Attacker |

---

## Detections

| Technique | Tactic | Method | Result |
|---|---|---|---|
| T1003.001 — LSASS Dump | Credential Access | Atomic Red Team | Blocked by Defender; Sysmon EventCode 10 still logged the attempt |
| T1059.001 — PowerShell | Execution | Atomic Red Team | CommandLine field shows encoded payloads and bypass flags |
| T1053.005 — Scheduled Task | Persistence | Atomic Red Team | schtasks.exe /create detected via Sysmon EventCode 1 |
| T1021.002 — SMB | Lateral Movement | Atomic Red Team | Admin share mapped; loopback test = no 4624 LogonType=3 (documented gap) |
| T1046 — Port Scan | Discovery | Nmap | No reliable host-based detection — needs network IDS (documented gap) |
| T1110 — Brute Force | Credential Access | Hydra | 13x EventCode 4625 detected with threshold query |

Detection queries → [`detection-rules/splunk_queries.md`](detection-rules/splunk_queries.md)  
Setup notes → [`docs/setup-notes.md`](docs/setup-notes.md)

---

## Known Gaps

- **T1021.002:** Loopback SMB doesn't generate EventCode 4624 LogonType=3. Real lateral movement from a separate machine would fire it.
- **T1046:** Host-based logs can't reliably detect port scans. Need Snort/Suricata or NetFlow.
- **T1053.005:** EventCode 4698 didn't fire on Windows 11 — used Sysmon process monitoring instead.
- **Kali log sources:** No auth.log/syslog (journald). Forwarding dpkg.log and vmware-network.log instead.
