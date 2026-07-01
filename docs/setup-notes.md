# Setup Notes

Step-by-step notes from building the lab. Includes all the commands, gotchas, and fixes.

---

## Step 1 — Splunk Enterprise

Downloaded Windows .msi from splunk.com, installed on Windows VM (192.168.56.130).

After first login at `http://localhost:8000`:

Create indexes (Settings → Indexes → New Index):
- `wineventlog`
- `sysmon`
- `syslog`

Set receiving port (Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port):
- Port: `9997`

---

## Step 2 — Sysmon

Downloaded from Microsoft Sysinternals. Used SwiftOnSecurity config.

Install (PowerShell as Administrator):
```powershell
cd C:\...\Downloads\Project2\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verify:
```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## Step 3 — Universal Forwarder (Windows)

Downloaded Windows 64-bit .msi from splunk.com. Pointed receiving indexer to `127.0.0.1:9997` during install.

Config files go in `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`.
See `splunk-configs/inputs.conf` and `splunk-configs/outputs.conf`.

**Fix: Sysmon permission issue**

Forwarder couldn't read the Sysmon/Operational log channel — only LocalSystem/Administrators allowed. Fix:
```powershell
sc.exe config SplunkForwarder obj= "LocalSystem"
Restart-Service SplunkForwarder
```

Verify data is flowing in Splunk:
```
index=wineventlog | head 10
index=sysmon | head 10
```

---

## Step 4 — Universal Forwarder (Kali)

Splunk.com was blocked on Kali's network so transferred the .deb file via Python HTTP server:

```powershell
# On Windows VM
python -m http.server 8080
```

```bash
# On Kali
wget http://192.168.56.130:8080/splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
sudo dpkg -i splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
```

Config files go in `/opt/splunkforwarder/etc/system/local/`.
See `splunk-configs/inputs_kali.conf` and `splunk-configs/outputs_kali.conf`.

**Fix: Windows firewall blocking port 9997**
```powershell
New-NetFirewallRule -DisplayName "Splunk Forwarder" -Direction Inbound -Protocol TCP -LocalPort 9997 -Action Allow
```

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

Verify in Splunk: `index=syslog` should return events with `host=kali`.

---

## Step 5 — Atomic Red Team

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Defender will flag things during install. Add exclusion:
```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

Run tests and save output:
```powershell
Invoke-AtomicTest T1003.001 *>&1 | Out-File -FilePath "T1003_001_output.txt"
Invoke-AtomicTest T1059.001 *>&1 | Out-File -FilePath "T1059_001_output.txt"
Invoke-AtomicTest T1053.005 *>&1 | Out-File -FilePath "T1053_005_output.txt"
Invoke-AtomicTest T1021.002 *>&1 | Out-File -FilePath "T1021_002_output.txt"
```

> The `*>&1` redirects all PowerShell streams. Without it the output file will be empty.

---

## Step 6 — Kali Attacks

**Open SMB through firewall (for nmap + brute force):**
```powershell
New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
```

**Set account lockout policy (so lockout events fire in Splunk):**
```powershell
net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30
```

**Nmap scan from Kali:**
```bash
nmap -sV -p 1-1000 192.168.56.130
```

**SMB brute force from Kali (T1110):**
```bash
for i in {1..15}; do smbclient //192.168.56.130/C$ -U administrator%wrongpass$i 2>/dev/null; echo "attempt $i"; done
```

Attempts 1-10 return `NT_STATUS_LOGON_FAILURE`, attempts 11-15 return `NT_STATUS_ACCOUNT_LOCKED_OUT` after hitting the lockout threshold. Both show up as EventCode 4625 in Splunk.

Note: Hydra's SMB module doesn't work against modern Windows 11 — use the smbclient loop instead.

---

## Step 7 — SOC Dashboard

Splunk → Dashboards → Create New Dashboard → Classic Dashboard
Name: `SOC Dashboard`

Add panels:
- Total Events Today (Single Value): `index=* earliest=-24h | stats count`
- Failed Logins Over Time (Line Chart): `earliest=0 index=wineventlog EventCode=4625 | timechart span=1h count`
- Top 10 Source IPs (Bar Chart): `earliest=0 index=wineventlog EventCode=4625 | rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)" | stats count by src_ip | sort -count | head 10`
- Events by Index (Bar Chart): `earliest=0 index=* | stats count by index | sort -count`

Set time range to **All Time** on each panel or add `earliest=0` — otherwise historical events won't show.
