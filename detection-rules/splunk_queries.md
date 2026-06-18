# Splunk Detection Rules — MITRE ATT&CK Mapped

All queries tested in this lab. Set time range to **All Time** or add `earliest=0` or results will be empty.

---

## T1003.001 — LSASS Credential Dumping
**Tactic:** Credential Access
**Index:** sysmon

```
index=sysmon
| search _raw="*lsass*" OR _raw="*mimikatz*" OR _raw="*minidump*" OR _raw="*procdump*"
| table _time, host, _raw
| sort -_time
```

**Lab result:** Windows Defender blocked actual execution but Sysmon still logged the attempt.

---

## T1110 — Brute Force (RDP)
**Tactic:** Credential Access
**Index:** wineventlog

```
earliest=0 index=wineventlog EventCode=4625
| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)"
| stats count by src_ip
| sort -count
```

**Lab result:** Hydra from Kali (192.168.56.129) generated 13 failed logins. Showed up clearly.

---

## T1059.001 — PowerShell Suspicious Execution
**Tactic:** Execution
**Index:** sysmon

```
index=sysmon
| search _raw="*powershell*" AND (_raw="*encoded*" OR _raw="*bypass*" OR _raw="*mimikatz*" OR _raw="*bloodhound*")
| table _time, host, _raw
| sort -_time
```

---

## T1053.005 — Scheduled Task Persistence
**Tactic:** Persistence
**Index:** sysmon

```
index=sysmon
| search _raw="*schtasks*" OR _raw="*AtomicTask*" OR _raw="*EventViewerBypass*" OR _raw="*CompMgmtBypass*"
| table _time, host, _raw
| sort -_time
```

**Note:** EventCode 4698 didn't fire on Windows 11 even after enabling audit policy. Used Sysmon as detection method instead.

---

## T1021.002 — SMB Lateral Movement
**Tactic:** Lateral Movement
**Index:** wineventlog

```
earliest=0 index=wineventlog EventCode=4624 LogonType=3
| table _time, host, Source_Network_Address, Account_Name
| sort -_time
```

**Note:** Loopback SMB didn't trigger 4624 LogonType=3. Would fire in a real multi-host environment.

---

## T1046 — Network Reconnaissance
**Tactic:** Discovery
**Index:** wineventlog

```
index=wineventlog EventCode=5156 OR EventCode=5157
| table _time, host, _raw
| sort -_time
```

**Note:** Nmap scans aren't reliably logged by Windows Security event logs. Need network-level IDS for proper detection.

---

## General Sysmon Search

```
index=sysmon
| stats count by EventCode
| sort -count
```

Common EventCodes:
- `1` = Process Create
- `3` = Network Connection
- `11` = File Create
- `13` = Registry Value Set
- `22` = DNS Query
