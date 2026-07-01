# T1046 — Network Service Discovery: Detection Gap

**Tactic:** Discovery  
**Technique:** [T1046](https://attack.mitre.org/techniques/T1046/)

## Detection Gap

Nmap SYN/version scans (`nmap -sV`) are **not visible** in Splunk when using only host-based log sources (Windows Security event logs, Sysmon).

**Why:** Windows Security audit logs record authentication and object access events — not incoming TCP connection attempts that do not complete a full session. A SYN scan sends TCP SYN packets and reads SYN-ACK/RST responses without completing the 3-way handshake, so no Windows event is generated.

**Sysmon EventID 3** (Network Connection) only logs *outbound* connections initiated by processes on the monitored host, not inbound scanning traffic.

## Detection Alternatives

| Tool | Approach | Notes |
|------|----------|-------|
| Suricata | `alert tcp any any -> $HOME_NET any (flags:S; threshold:type both, track by_src, count 20, seconds 60; msg:"Port Scan Detected";)` | Real-time IDS rule |
| Zeek (Bro) | `Scan::*` notices | Network flow analysis |
| Snort | Portscan preprocessor | Detects threshold of failed connections |
| Windows Firewall logging | Enable verbose logging; parse with Splunk TA | Captures dropped/allowed connections |
| Sysmon EventID 3 | Only logs *process-initiated* outbound connections | Not useful for detecting inbound scans |

## Evidence from Lab

Lab ran: `nmap -sV -p 1-1000 192.168.56.130` from Kali (192.168.56.129)  
Result: Port 445 open. No events appeared in `index=wineventlog` or `index=sysmon`.  
Screenshot evidence: `screenshots/T1110-nmap.png`
