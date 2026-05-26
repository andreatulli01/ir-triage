# IR-TRIAGE 🔍

> A lightweight, zero-infrastructure incident response triage tool for security analysts and students.  
> Cross-platform: Windows · Linux · macOS — single Python file, runs anywhere in under 60 seconds.

 The Problem

Most IR automation tools require heavy infrastructure before you can even start:

| Tool | What it needs |
|---|---|
| TheHive | Full server deployment |
| GRR Rapid Response | Agent installed on every target machine |
| Velociraptor | Server + fleet enrollment |
| Elasticsearch-based scripts | Running ELK stack |

When you're responding to an incident, you don't have time for that. You need answers **now**.

What IR-TRIAGE Does

Runs 7 modules against a live system and produces a severity-scored terminal report — no setup, no config, no dependencies beyond three pip packages.

```
╔══════════════════════════════════════════════════════╗
║        IR-TRIAGE v1.1  ·  Incident Response Tool     ║
║   Zero-infra · Windows · Linux · macOS · Scored      ║
╚══════════════════════════════════════════════════════╝
```
Modules

| Module | What it checks |

| 1 | System Info | Hostname, OS, uptime, privilege level |

| 2 | Running Processes | All processes flagged against known malware names |

| 3 | Network Connections | Active connections, external IPs, suspicious ports |

| 4 | Persistence Mechanisms | LaunchAgents, cron, systemd, registry run keys, startup folder, shell files |

| 5 | Log Analysis | Failed logins, sudo usage, SSH attempts |

| 6 | Process Hashes | SHA-256 + MD5 of all running executables |

| 7 | Threat Intel | VirusTotal hash lookup + AbuseIPDB IP reputation (optional) |

Severity Scoring

Every finding is automatically scored:

```
[CRITICAL]  Connection to known C2 port (Metasploit default, Tor, IRC)
[HIGH]      Suspicious process name, brute force detected, malicious VT hash
[MEDIUM]    Registry run keys, non-standard scheduled tasks, cron entries
[LOW]       Running without admin privileges, minor anomalies
```

---

Quickstart

```bash
# 1. Clone
git clone https://github.com/andreatulli01/ir-triage.git
cd ir-triage

# 2. Install dependencies
pip install psutil colorama requests

# 3. Run
python3 ir_triage.py
```

> macOS: Use a virtual environment to avoid the Homebrew-managed Python restriction:
> ```bash
> python3 -m venv ~/ir-env && source ~/ir-env/bin/activate
> pip install psutil colorama requests
> python3 ir_triage.py
> ```

> Linux/Windows: Run as root/admin for full visibility:
> ```bash
> sudo python3 ir_triage.py   # Linux
> # Run terminal as Administrator on Windows
> ```

---

CLI Options

```
python3 ir_triage.py                          # full triage
python3 ir_triage.py --vt-key YOUR_KEY        # + VirusTotal hash lookups
python3 ir_triage.py --abuse-key YOUR_KEY     # + AbuseIPDB IP reputation
python3 ir_triage.py --skip-hashes            # skip hash extraction (faster)
python3 ir_triage.py --skip-logs              # skip log analysis
```

Getting Free API Keys

| Service | URL | Free tier |
| VirusTotal | https://virustotal.com | 4 lookups/min |
| AbuseIPDB | https://abuseipdb.com | 1,000 checks/day |

---

## What It Detects

**Suspicious Processes**
Flags process names matching known offensive tools: `mimikatz`, `meterpreter`, `netcat`, `xmrig`, `bloodhound`, `cobalt`, `lazagne`, and more.

Suspicious Network Ports
Automatically flags connections to known attacker infrastructure:

| Port | Known use |
| 4444 | Metasploit default listener |
| 9050 | Tor SOCKS proxy |
| 6667/6666 | IRC Command & Control |
| 31337 | Back Orifice |
| 1337 | Common backdoor port |

Persistence Mechanisms**

- macOS: LaunchAgents, LaunchDaemons, Login Items, `.zshrc`/`.zprofile`
- Linux: Cron jobs, systemd services, `.bashrc`/`.profile`
- Windows: Registry Run keys, Scheduled Tasks, Startup folder

Log Analysis

- macOS: Unified Log — failed auth, sudo usage, SSH attempts
- Linux: `/var/log/auth.log` — failed logins, BREAK-IN ATTEMPT, ROOT LOGIN
- Windows: Security Event Log — Event ID 4625 (failed logon)

---

Why This Is Different

- ✅ Zero infrastructure — one file, three pip packages
- ✅ Truly cross-platform — Windows, Linux, and macOS all supported
- ✅ Severity scoring — findings are prioritized, not just dumped
- ✅ Persistence detection — often missed by lightweight scripts
- ✅ Optional threat intel — works without API keys, enhanced with them
- ✅ Runs in under 60 seconds on a typical machine

Requirements

```
psutil
colorama
requests
```

Python 3.7+

---

License

MIT — free to use, modify, and distribute.

---

Author

Andrea Tulli 
Bachelor of Information Technology — Cybersecurity & Networking, UTS Sydney  
[LinkedIn](https://au.linkedin.com/in/andrea-tulli-a0341722a)
