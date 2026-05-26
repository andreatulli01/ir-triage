#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║          IR-TRIAGE v1.1 — by Andrea Tulli            ║
║    Automated Incident Response Triage Framework      ║
║    Cross-platform: Windows · Linux · macOS           ║
╚══════════════════════════════════════════════════════╝

Usage:
  python ir_triage.py                          # basic triage
  python ir_triage.py --vt-key YOUR_KEY        # + VirusTotal lookups
  python ir_triage.py --abuse-key YOUR_KEY     # + AbuseIPDB IP reputation
  python ir_triage.py --skip-hashes            # faster, skip hash extraction
  python ir_triage.py --skip-logs              # skip log analysis

Install deps:
  pip install psutil colorama requests
"""

import os
import sys
import platform
import socket
import hashlib
import datetime
import subprocess
import argparse
from collections import defaultdict

# ─────────────────────────────────────────────
# DEPENDENCY CHECKS
# ─────────────────────────────────────────────

try:
    import psutil
except ImportError:
    print("[!] psutil not installed. Run: pip install psutil")
    sys.exit(1)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

# ─────────────────────────────────────────────
# COLOR HELPERS
# ─────────────────────────────────────────────

def _c(text, code):
    return (code + text + Style.RESET_ALL) if COLORS else text

def red(t):     return _c(t, Fore.RED)
def green(t):   return _c(t, Fore.GREEN)
def yellow(t):  return _c(t, Fore.YELLOW)
def cyan(t):    return _c(t, Fore.CYAN)
def magenta(t): return _c(t, Fore.MAGENTA)

def bold(t):
    return (_c(t, Style.BRIGHT)) if COLORS else t

# ─────────────────────────────────────────────
# FINDINGS ENGINE
# ─────────────────────────────────────────────

FINDINGS = []  # [{severity, category, description}]

def add_finding(severity, category, description):
    FINDINGS.append({
        "severity":    severity,
        "category":    category,
        "description": description,
    })

SEVERITY_FN = {
    "CRITICAL": red,
    "HIGH":     yellow,
    "MEDIUM":   lambda t: _c(t, Fore.CYAN),
    "LOW":      lambda t: _c(t, Fore.WHITE),
    "INFO":     green,
}

def sev(s):
    fn = SEVERITY_FN.get(s, lambda t: t)
    return fn(f"[{s:8s}]")

# ─────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────

def banner():
    print()
    print(cyan("╔══════════════════════════════════════════════════════╗"))
    print(cyan("║") + bold("        IR-TRIAGE v1.1  ·  Incident Response Tool     ") + cyan("║"))
    print(cyan("║") + "   Zero-infra · Windows · Linux · macOS · Scored      " + cyan("║"))
    print(cyan("╚══════════════════════════════════════════════════════╝"))
    print()

def section(n, title):
    print()
    line = f"[{n}] {title}"
    print(cyan("━" * 18) + " " + bold(line) + " " + cyan("━" * 18))

def ok(msg):   print(f"  {green('[✓]')} {msg}")
def warn(msg): print(f"  {yellow('[!]')} {msg}")
def flag(msg): print(f"  {red('[⚠]')} {msg}")
def info(msg): print(f"  {cyan('[*]')} {msg}")

# ─────────────────────────────────────────────
# KNOWN SUSPICIOUS VALUES
# ─────────────────────────────────────────────

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "meterpreter", "nc", "ncat", "netcat", "psexec",
    "wce", "fgdump", "pwdump", "beacon", "cobalt", "empire",
    "xmrig", "coinhive", "cryptominer", "payload", "rat",
    "keylogger", "lazagne", "crackmapexec", "bloodhound",
}

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1234:  "Common RAT port",
    31337: "Back Orifice / elite port",
    6667:  "IRC Command & Control",
    6666:  "IRC Command & Control",
    9001:  "Tor relay",
    9050:  "Tor SOCKS proxy",
    1337:  "Common backdoor port",
    5554:  "Sasser worm",
    8080:  "Alternate HTTP / proxy (flag if unexpected)",
}

PRIVATE_PREFIXES = ("127.", "192.168.", "10.", "172.16.", "172.17.",
                    "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                    "172.28.", "172.29.", "172.30.", "172.31.", "::1", "fe80")

# ─────────────────────────────────────────────
# MODULE 1 — SYSTEM INFO
# ─────────────────────────────────────────────

def module_system_info():
    section(1, "SYSTEM INFO")

    now       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname  = socket.gethostname()
    os_info   = platform.platform()
    user      = os.getenv("USERNAME") or os.getenv("USER") or "unknown"
    boot_ts   = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime    = datetime.datetime.now() - boot_ts
    uptime_h  = int(uptime.total_seconds() // 3600)
    uptime_m  = int((uptime.total_seconds() % 3600) // 60)

    # Admin / root check
    is_admin = False
    try:
        if platform.system() == "Windows":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
    except Exception:
        pass

    priv_str = green("YES (elevated)") if is_admin else yellow("NO — some checks may be limited")

    print(f"  Timestamp    : {now}")
    print(f"  Hostname     : {bold(hostname)}")
    print(f"  OS           : {os_info}")
    print(f"  Current User : {user}")
    print(f"  Privileges   : {priv_str}")
    print(f"  System Boot  : {boot_ts.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Uptime       : {uptime_h}h {uptime_m}m")

    if not is_admin:
        add_finding("LOW", "System", "Script not running as admin/root — some modules will have reduced visibility")

# ─────────────────────────────────────────────
# MODULE 2 — RUNNING PROCESSES
# ─────────────────────────────────────────────

def module_processes():
    section(2, "RUNNING PROCESSES")
    print(f"  {bold('PID'):<10} {bold('NAME'):<30} {bold('USER'):<22} {bold('CPU%'):<8} {bold('MEM%')}")
    print("  " + "─" * 78)

    flagged = []

    procs = sorted(
        psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']),
        key=lambda p: p.info.get('cpu_percent') or 0,
        reverse=True
    )

    for proc in procs:
        try:
            info = proc.info
            name  = info.get('name') or "?"
            user  = (info.get('username') or "?").split("\\")[-1]
            cpu   = f"{info.get('cpu_percent') or 0:.1f}%"
            mem   = f"{info.get('memory_percent') or 0:.2f}%"
            pid   = str(info['pid'])

            is_sus = name.lower().rstrip(".exe") in SUSPICIOUS_PROCESS_NAMES

            line = f"  {pid:<10} {name:<30} {user:<22} {cpu:<8} {mem}"

            if is_sus:
                print(red(line) + red("  ← SUSPICIOUS NAME"))
                flagged.append(name)
                add_finding("HIGH", "Process", f"Suspicious process detected: {name} (PID {pid})")
            else:
                print(line)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print()
    if flagged:
        flag(f"{len(flagged)} suspicious process name(s) detected: {', '.join(flagged)}")
    else:
        ok("No suspicious process names detected in running list")

# ─────────────────────────────────────────────
# MODULE 3 — NETWORK CONNECTIONS
# ─────────────────────────────────────────────

def module_network():
    section(3, "ACTIVE NETWORK CONNECTIONS")
    print(f"  {bold('LOCAL ADDRESS'):<32} {bold('REMOTE ADDRESS'):<32} {bold('STATUS'):<14} {bold('PID')}")
    print("  " + "─" * 88)

    external_ips = set()
    suspicious_conns = []

    try:
        conns = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        warn("Access denied — run as admin/root for full network visibility")
        return set()

    for conn in conns:
        try:
            laddr  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
            raddr  = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
            status = conn.status or "—"
            pid    = str(conn.pid) if conn.pid else "—"

            sus_reason = None
            if conn.raddr:
                sus_reason = SUSPICIOUS_PORTS.get(conn.raddr.port)
                rip = conn.raddr.ip
                if not any(rip.startswith(p) for p in PRIVATE_PREFIXES):
                    external_ips.add(rip)

            line = f"  {laddr:<32} {raddr:<32} {status:<14} {pid}"

            if sus_reason:
                print(red(line) + red(f"  ← {sus_reason}"))
                suspicious_conns.append((conn.raddr.ip, conn.raddr.port, sus_reason))
                add_finding("CRITICAL", "Network",
                            f"Connection to suspicious port {conn.raddr.port} ({sus_reason}) — remote: {conn.raddr.ip}")
            elif status == "ESTABLISHED" and conn.raddr:
                print(yellow(line))
            else:
                print(line)
        except Exception:
            continue

    print()
    if external_ips:
        info(f"External IPs with active connections ({len(external_ips)}):")
        for ip in external_ips:
            print(f"    → {yellow(ip)}")
    else:
        ok("No external IP connections detected")

    if suspicious_conns:
        flag(f"{len(suspicious_conns)} connection(s) to known suspicious port(s)")
    
    return external_ips

# ─────────────────────────────────────────────
# MODULE 4 — PERSISTENCE CHECK
# ─────────────────────────────────────────────

def module_persistence():
    section(4, "PERSISTENCE MECHANISMS")
    os_type = platform.system()

    if os_type == "Linux":
        _persistence_linux()
    elif os_type == "Windows":
        _persistence_windows()
    elif os_type == "Darwin":
        _persistence_macos()
    else:
        warn(f"Persistence check not implemented for {os_type}")

# ── macOS ──────────────────────────────────

def _persistence_macos():
    import re as _re
    # 1. LaunchAgents / LaunchDaemons
    # Strategy: parse each plist and inspect what it actually RUNS
    # Flag only if the binary path is suspicious — not just because it's non-Apple
    launch_paths = [
        (os.path.expanduser("~/Library/LaunchAgents"),  "User LaunchAgents"),
        ("/Library/LaunchAgents",                        "System LaunchAgents"),
        ("/Library/LaunchDaemons",                       "System LaunchDaemons"),
    ]

    # Paths that are always suspicious for a binary to live in
    suspicious_bin_paths = [
        "/tmp/", "/var/tmp/", "/private/tmp/",
        "/Users/Shared/",
        os.path.expanduser("~/Downloads/"),
        os.path.expanduser("~/Library/Caches/"),
    ]

    # Suspicious commands in plist args
    suspicious_patterns = [
        "curl", "wget", "bash -i", "python -c", "python3 -c",
        "base64", "ncat", "netcat",
    ]

    # Gibberish: short name with no dots (no reverse-domain format)
    gibberish_re = _re.compile(r'^[a-zA-Z0-9_-]{4,16}\.plist$')

    print(f"  {bold('[ LaunchAgents / LaunchDaemons ]')}")
    flagged_any = False

    for path, label in launch_paths:
        if not os.path.isdir(path):
            continue
        try:
            plists = [f for f in os.listdir(path) if f.endswith(".plist")]
            for plist_name in plists:
                full_path = os.path.join(path, plist_name)
                reasons = []
                base = plist_name.replace(".plist", "")

                # Check 1: gibberish filename (no dots = no reverse-domain = suspicious)
                if gibberish_re.match(plist_name) and "." not in base:
                    reasons.append("unusual filename — no reverse-domain format")

                # Check 2: parse plist and inspect binary path and args
                try:
                    result = subprocess.run(
                        ["plutil", "-convert", "xml1", "-o", "-", full_path],
                        capture_output=True, text=True, timeout=3
                    )
                    content = result.stdout
                    for sus in suspicious_bin_paths:
                        if sus in content:
                            reasons.append(f"binary in suspicious path: {sus.rstrip('/')}")
                    for pat in suspicious_patterns:
                        if pat in content:
                            reasons.append(f"suspicious argument: '{pat}'")
                except Exception:
                    pass

                if reasons:
                    severity = "HIGH" if len(reasons) > 1 else "MEDIUM"
                    flag(f"{plist_name}")
                    for r in reasons:
                        print(f"      reason: {red(r)}")
                    add_finding(severity, "Persistence",
                                f"Suspicious LaunchAgent: {full_path} — {'; '.join(reasons)}")
                    flagged_any = True

        except PermissionError:
            warn(f"{label}: permission denied")

    if not flagged_any:
        ok("No suspicious LaunchAgents or LaunchDaemons detected")


    # 2. Login Items (via osascript)
    print(f"\n  {bold('[ Login Items ]')}")
    try:
        result = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get the name of every login item'],
            capture_output=True, text=True, timeout=5
        )
        items_raw = result.stdout.strip()
        if items_raw:
            items = [i.strip() for i in items_raw.split(",") if i.strip()]
            # Known legitimate login item names — just list them, don't flag
            known_safe = {
                "dropbox", "steam", "zoom", "slack", "spotify", "1password",
                "alfred", "bartender", "rectangle", "magnet", "amphetamine",
                "nordvpn", "expressvpn", "tunnelblick", "viscosity",
                "lm studio", "warp", "iterm2", "nova", "tower", "fork",
                "visual studio code", "cursor", "figma", "notion",
                "google drive", "onedrive", "box", "creative cloud",
                "backblaze", "carbon copy cloner", "superduper",
            }
            suspicious_items = []
            for item in items:
                item_lower = item.lower()
                if any(safe in item_lower for safe in known_safe):
                    print(f"    {green('→')} {item} (known app)")
                elif item.endswith(".exe"):
                    print(f"    {red('→')} {item}")
                    suspicious_items.append(item)
                    add_finding("HIGH", "Persistence",
                                f"Login item with .exe extension on macOS: {item}")
                else:
                    print(f"    {yellow('→')} {item} (unknown — verify manually)")
                    suspicious_items.append(item)
                    add_finding("LOW", "Persistence", f"Unrecognised login item: {item}")
        else:
            ok("No login items found")
    except Exception:
        warn("Could not query login items (needs System Events access)")

    # 3. Shell startup file anomalies (zsh is default on modern macOS)
    print(f"\n  {bold('[ Shell Startup Files ]')}")
    shell_files = [
        os.path.expanduser("~/.zshrc"),
        os.path.expanduser("~/.zprofile"),
        os.path.expanduser("~/.bash_profile"),
        os.path.expanduser("~/.bashrc"),
        "/etc/zshrc",
        "/etc/profile",
    ]
    # Always suspicious regardless of context
    definite_patterns = ["curl ", "wget ", "nc ", "bash -i", "python -c", "python3 -c", "/tmp/", "nohup"]
    # Only suspicious when combined with a network/encoding trigger
    conditional_patterns = ["eval", "exec", "base64", "osascript", "chmod +x"]
    conditional_triggers = ["curl", "wget", "http", "base64", "/tmp/", "nc ", "bash -i"]
    # Known-safe substrings — skip lines containing these
    safe_substrings = [
        "dircolors", "lesspipe", "nvm use", "rbenv", "pyenv",
        "thefuck", "zoxide", "starship", "brew shellenv",
        "conda init", "mise activate", "fnm env",
    ]

    for f in shell_files:
        if not os.path.exists(f):
            continue
        try:
            suspicious_lines = []
            with open(f) as fh:
                for l in fh:
                    line = l.strip()
                    if not line or line.startswith("#"):
                        continue
                    if any(safe in line for safe in safe_substrings):
                        continue
                    if any(pat in line for pat in definite_patterns):
                        suspicious_lines.append(line)
                        continue
                    if any(pat in line for pat in conditional_patterns):
                        if any(trig in line for trig in conditional_triggers):
                            suspicious_lines.append(line)
            if suspicious_lines:
                for sl in suspicious_lines:
                    flag(f"{f}: {red(sl)}")
                    add_finding("HIGH", "Persistence",
                                f"Suspicious command in {f}: {sl}")
            else:
                ok(f"{f}")
        except PermissionError:
            warn(f"{f}: permission denied")

    # 4. Cron jobs (macOS still supports cron)
    print(f"\n  {bold('[ Cron Jobs ]')}")
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("#")]
        if lines:
            warn("User crontab entries found:")
            for l in lines:
                print(f"    {yellow(l)}")
                add_finding("MEDIUM", "Persistence", f"Cron entry: {l.strip()}")
        else:
            ok("No user crontab entries")
    except Exception:
        warn("Could not query crontab")


# ── Linux ──────────────────────────────────

def _persistence_linux():
    # 1. Cron jobs
    print(f"  {bold('[ Cron Jobs ]')}")
    cron_files = ["/etc/crontab", "/etc/cron.d"]
    for path in cron_files:
        if os.path.isfile(path):
            _print_cron_file(path)
        elif os.path.isdir(path):
            for f in os.listdir(path):
                _print_cron_file(os.path.join(path, f))

    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("#")]
        if lines:
            warn("Current user crontab entries found:")
            for l in lines:
                print(f"    {yellow(l)}")
                add_finding("MEDIUM", "Persistence", f"User cron entry: {l.strip()}")
        else:
            ok("No user crontab entries")
    except Exception:
        pass

    # 2. Systemd non-standard services
    print(f"\n  {bold('[ Systemd Enabled Services (non-system) ]')}")
    known = {"ssh", "cron", "rsyslog", "ufw", "snapd", "networkd",
             "resolved", "dbus", "accounts", "apt", "atd", "fwupd",
             "gdm", "lightdm", "polkit", "systemd", "udisks", "upower"}
    try:
        result = subprocess.run(
            ["systemctl", "list-unit-files", "--state=enabled", "--type=service", "--no-legend"],
            capture_output=True, text=True
        )
        non_standard = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts:
                svc = parts[0].replace(".service", "")
                if not any(k in svc.lower() for k in known):
                    non_standard.append(svc)

        if non_standard:
            for s in non_standard:
                print(f"    → {yellow(s)}")
                add_finding("LOW", "Persistence", f"Non-standard systemd service enabled: {s}")
        else:
            ok("No non-standard systemd services found")
    except Exception:
        warn("Could not query systemd")

    # 3. Shell startup file anomalies
    print(f"\n  {bold('[ Shell Startup Files ]')}")
    shell_files = [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.profile"),
        os.path.expanduser("~/.bash_profile"),
        "/etc/profile",
        "/etc/bash.bashrc",
    ]
    # Always suspicious regardless of context
    definite_patterns = ["curl ", "wget ", "nc ", "bash -i", "python -c", "python3 -c", "/tmp/", "nohup"]
    # Only suspicious when combined with a network/encoding trigger
    conditional_patterns = ["eval", "exec", "base64", "chmod +x"]
    conditional_triggers = ["curl", "wget", "http", "base64", "/tmp/", "nc ", "bash -i"]
    # Known-safe substrings — skip lines containing these
    safe_substrings = [
        "dircolors", "lesspipe", "nvm use", "rbenv", "pyenv",
        "thefuck", "zoxide", "starship", "brew shellenv",
        "conda init", "mise activate", "fnm env",
    ]

    for f in shell_files:
        if os.path.exists(f):
            try:
                suspicious_lines = []
                with open(f) as fh:
                    for l in fh:
                        line = l.strip()
                        if not line or line.startswith("#"):
                            continue
                        if any(safe in line for safe in safe_substrings):
                            continue
                        if any(pat in line for pat in definite_patterns):
                            suspicious_lines.append(line)
                            continue
                        if any(pat in line for pat in conditional_patterns):
                            if any(trig in line for trig in conditional_triggers):
                                suspicious_lines.append(line)
                if suspicious_lines:
                    for sl in suspicious_lines:
                        flag(f"{f}: {red(sl)}")
                        add_finding("HIGH", "Persistence", f"Suspicious command in {f}: {sl}")
                else:
                    ok(f"{f}")
            except PermissionError:
                warn(f"{f}: permission denied")

def _print_cron_file(path):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if lines:
            warn(f"Cron entries in {path}:")
            for l in lines:
                print(f"    {yellow(l)}")
    except (PermissionError, IsADirectoryError):
        pass

# ── Windows ────────────────────────────────

def _persistence_windows():
    # 1. Registry Run keys
    print(f"  {bold('[ Registry Run Keys ]')}")
    try:
        import winreg
        run_keys = [
            (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKCU\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKLM\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
        ]
        found_any = False
        for hive, subkey, label in run_keys:
            try:
                key = winreg.OpenKey(hive, subkey)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        print(f"    [{label}] {yellow(name)} = {val}")
                        add_finding("MEDIUM", "Persistence", f"Registry run key [{label}]: {name} = {val}")
                        found_any = True
                        i += 1
                    except OSError:
                        break
            except (PermissionError, FileNotFoundError):
                warn(f"Access denied: {label}")
        if not found_any:
            ok("No registry run key entries found")
    except ImportError:
        warn("winreg not available")

    # 2. Scheduled Tasks
    print(f"\n  {bold('[ Scheduled Tasks (non-Microsoft) ]')}")
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST"],
            capture_output=True, text=True, shell=True
        )
        current_task = ""
        found_tasks = False
        for line in result.stdout.splitlines():
            if line.startswith("TaskName:"):
                current_task = line.split(":", 1)[1].strip()
            if current_task and "\\Microsoft\\" not in current_task:
                if "Task To Run:" in line:
                    run_cmd = line.split(":", 1)[1].strip()
                    print(f"    {yellow(current_task)} → {run_cmd}")
                    add_finding("MEDIUM", "Persistence", f"Scheduled task: {current_task} → {run_cmd}")
                    found_tasks = True
        if not found_tasks:
            ok("No non-Microsoft scheduled tasks found")
    except Exception as e:
        warn(f"Could not query scheduled tasks: {e}")

    # 3. Startup folder
    print(f"\n  {bold('[ Startup Folder ]')}")
    startup = os.path.join(
        os.getenv("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    )
    if os.path.exists(startup):
        items = [i for i in os.listdir(startup) if not i.startswith(".")]
        if items:
            for item in items:
                flag(f"Startup folder: {item}")
                add_finding("HIGH", "Persistence", f"Item in user Startup folder: {item}")
        else:
            ok("Startup folder is empty")
    else:
        warn("Could not locate Startup folder")

# ─────────────────────────────────────────────
# MODULE 5 — LOG ANALYSIS
# ─────────────────────────────────────────────

def module_logs():
    section(5, "LOG ANALYSIS")
    os_type = platform.system()

    if os_type == "Linux":
        _logs_linux()
    elif os_type == "Windows":
        _logs_windows()
    elif os_type == "Darwin":
        _logs_macos()

# ── macOS ──────────────────────────────────

def _logs_macos():
    info("Querying macOS Unified Log (last 24h) — this may take a few seconds...\n")

    # 1. Failed authentication attempts
    print(f"  {bold('[ Failed Authentication ]')}")
    try:
        result = subprocess.run(
            ["log", "show",
             "--predicate", "eventMessage CONTAINS 'failed' AND eventMessage CONTAINS 'authentication'",
             "--last", "24h",
             "--style", "compact"],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        count = len(lines)

        if count > 20:
            flag(f"Failed authentication events in last 24h: {count}  ← investigate")
            add_finding("HIGH", "Authentication",
                        f"{count} failed authentication events in macOS unified log (last 24h)")
            for l in lines[-5:]:
                print(f"    {red(l[:120])}")
        elif count > 0:
            warn(f"Failed authentication events in last 24h: {count}")
            add_finding("LOW", "Authentication",
                        f"{count} failed authentication events in macOS unified log (last 24h)")
            for l in lines[-3:]:
                print(f"    {yellow(l[:120])}")
        else:
            ok("No failed authentication events in last 24h")

    except subprocess.TimeoutExpired:
        warn("Log query timed out — try running with sudo for faster access")
    except FileNotFoundError:
        warn("'log' command not found — requires macOS 10.12+")
    except Exception as e:
        warn(f"Could not query unified log: {e}")

    # 2. Sudo usage
    print(f"\n  {bold('[ Sudo Usage (last 24h) ]')}")
    try:
        result = subprocess.run(
            ["log", "show",
             "--predicate", "eventMessage CONTAINS 'sudo'",
             "--last", "24h",
             "--style", "compact"],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        if lines:
            info(f"Sudo events found ({min(len(lines), 5)} shown):")
            for l in lines[-5:]:
                print(f"    {yellow(l[:120])}")
        else:
            ok("No sudo activity in last 24h")
    except subprocess.TimeoutExpired:
        warn("Sudo log query timed out")
    except Exception as e:
        warn(f"Could not query sudo logs: {e}")

    # 3. SSH login attempts
    print(f"\n  {bold('[ SSH Login Attempts (last 24h) ]')}")
    try:
        result = subprocess.run(
            ["log", "show",
             "--predicate", "processImagePath CONTAINS 'sshd'",
             "--last", "24h",
             "--style", "compact"],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        failed_ssh = [l for l in lines if "failed" in l.lower() or "invalid" in l.lower()]

        if failed_ssh:
            flag(f"Failed SSH attempts: {len(failed_ssh)}")
            add_finding("HIGH", "Authentication",
                        f"{len(failed_ssh)} failed SSH login attempts in last 24h")
            for l in failed_ssh[-5:]:
                print(f"    {red(l[:120])}")
        else:
            ok("No failed SSH attempts in last 24h")
    except subprocess.TimeoutExpired:
        warn("SSH log query timed out")
    except Exception as e:
        warn(f"Could not query SSH logs: {e}")


# ── Linux ──────────────────────────────────

    log_candidates = ["/var/log/auth.log", "/var/log/secure"]

    parsed = False
    for log_path in log_candidates:
        if not os.path.exists(log_path):
            continue

        info(f"Parsing: {log_path}")
        failed_count  = 0
        sudo_events   = []
        unusual_lines = []

        try:
            with open(log_path, "r", errors="ignore") as f:
                for line in f:
                    if "Failed password" in line or "authentication failure" in line:
                        failed_count += 1
                    if "sudo" in line and "COMMAND" in line:
                        sudo_events.append(line.strip())
                    if any(x in line for x in ["Invalid user", "ROOT LOGIN", "BREAK-IN ATTEMPT"]):
                        unusual_lines.append(line.strip())

            # Failed logins
            if failed_count > 50:
                flag(f"Failed login attempts: {failed_count}  ← likely brute force")
                add_finding("CRITICAL", "Authentication",
                            f"{failed_count} failed logins in {log_path} — possible brute force attack")
            elif failed_count > 10:
                warn(f"Failed login attempts: {failed_count}")
                add_finding("HIGH", "Authentication",
                            f"{failed_count} failed logins in {log_path}")
            elif failed_count > 0:
                info(f"Failed login attempts: {failed_count}")
                add_finding("LOW", "Authentication",
                            f"{failed_count} failed logins in {log_path}")
            else:
                ok("No failed login attempts found")

            # Sudo activity
            if sudo_events:
                info(f"Recent sudo commands ({min(len(sudo_events), 5)} shown):")
                for e in sudo_events[-5:]:
                    print(f"    {yellow(e[-120:])}")
            else:
                ok("No sudo activity recorded")

            # Unusual events
            if unusual_lines:
                flag(f"Unusual authentication events ({len(unusual_lines)}):")
                for e in unusual_lines[-5:]:
                    print(f"    {red(e[-120:])}")
                add_finding("HIGH", "Authentication",
                            f"{len(unusual_lines)} unusual auth events (Invalid user / BREAK-IN ATTEMPT / ROOT LOGIN)")

            parsed = True
            break

        except PermissionError:
            flag("Permission denied reading auth log — run as root for full visibility")
            add_finding("LOW", "System", f"Could not read {log_path} — needs root")
            break

    if not parsed and not os.path.exists("/var/log/auth.log") and not os.path.exists("/var/log/secure"):
        warn("No auth log found at expected paths (/var/log/auth.log or /var/log/secure)")


def _logs_windows():
    info("Querying Windows Security Event Log (IDs: 4625 failed logon, 4648 explicit creds)")

    try:
        # Count recent failed logons
        ps_cmd = (
            '$events = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} '
            '-MaxEvents 100 -ErrorAction SilentlyContinue; '
            'Write-Output $events.Count'
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, shell=True, timeout=15
        )
        count_str = result.stdout.strip()
        count = int(count_str) if count_str.isdigit() else 0

        if count > 20:
            flag(f"Failed logon events (4625): {count}  ← investigate")
            add_finding("HIGH", "Authentication",
                        f"{count} failed Windows logon events (Event ID 4625)")
        elif count > 0:
            warn(f"Failed logon events (4625): {count}")
            add_finding("LOW", "Authentication",
                        f"{count} failed Windows logon events")
        else:
            ok("No recent failed logon events (4625)")

    except subprocess.TimeoutExpired:
        warn("Event log query timed out")
    except Exception as e:
        warn(f"Could not query Windows event log: {e}")

# ─────────────────────────────────────────────
# MODULE 6 — PROCESS HASH EXTRACTION
# ─────────────────────────────────────────────

def module_hashes():
    section(6, "PROCESS EXECUTABLE HASHES")
    info("Hashing process executables (SHA-256 + MD5) for threat intel lookup\n")

    hashes   = {}
    seen     = set()
    skipped  = 0

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info.get('exe')
            if exe and exe not in seen and os.path.isfile(exe):
                seen.add(exe)
                with open(exe, 'rb') as f:
                    data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                md5    = hashlib.md5(data).hexdigest()
                hashes[exe] = {
                    "name":   proc.info.get('name', '?'),
                    "sha256": sha256,
                    "md5":    md5,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError):
            skipped += 1
            continue

    displayed = list(hashes.items())[:25]
    for path, h in displayed:
        print(f"  {bold(h['name'])}")
        print(f"    Path   : {path}")
        print(f"    SHA256 : {cyan(h['sha256'])}")
        print(f"    MD5    : {h['md5']}")
        print()

    total = len(hashes)
    info(f"Hashed {total} unique executables" + (f" ({skipped} skipped — access denied)" if skipped else ""))

    return hashes

# ─────────────────────────────────────────────
# MODULE 7 — THREAT INTEL
# ─────────────────────────────────────────────

def module_threat_intel(external_ips, process_hashes, vt_key=None, abuse_key=None):
    section(7, "THREAT INTELLIGENCE LOOKUPS")

    if not REQUESTS_AVAILABLE:
        warn("'requests' library not installed — skipping threat intel")
        warn("Fix: pip install requests")
        return

    if not vt_key and not abuse_key:
        warn("No API keys provided — threat intel module disabled")
        info("Enable with: --vt-key YOUR_VT_KEY  and/or  --abuse-key YOUR_ABUSEIPDB_KEY")
        info("Free keys:   https://virustotal.com  /  https://abuseipdb.com")
        return

    # ── AbuseIPDB ─────────────────────────────
    if abuse_key and external_ips:
        print(f"  {bold('[ AbuseIPDB — IP Reputation ]')}")
        for ip in list(external_ips)[:8]:
            try:
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    timeout=6,
                )
                d       = resp.json().get("data", {})
                score   = d.get("abuseConfidenceScore", 0)
                country = d.get("countryCode", "?")
                reports = d.get("totalReports", 0)
                isp     = d.get("isp", "?")

                label = f"{ip:<18} score={score}%  reports={reports}  country={country}  isp={isp}"
                if score >= 50:
                    flag(label)
                    add_finding("CRITICAL", "Threat Intel",
                                f"AbuseIPDB: {ip} — confidence score {score}% ({reports} reports)")
                elif score > 0:
                    warn(label)
                    add_finding("MEDIUM", "Threat Intel",
                                f"AbuseIPDB: {ip} — low-confidence abuse score {score}%")
                else:
                    ok(label)

            except requests.RequestException as e:
                warn(f"AbuseIPDB request failed for {ip}: {e}")
    elif abuse_key:
        info("No external IPs to check against AbuseIPDB")

    # ── VirusTotal ────────────────────────────
    if vt_key and process_hashes:
        print(f"\n  {bold('[ VirusTotal — Process Hash Lookup ]')}")
        for path, h in list(process_hashes.items())[:5]:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{h['sha256']}",
                    headers={"x-apikey": vt_key},
                    timeout=8,
                )
                if resp.status_code == 200:
                    attrs      = resp.json()["data"]["attributes"]
                    stats      = attrs.get("last_analysis_stats", {})
                    malicious  = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total_eng  = sum(stats.values())

                    result_str = f"{h['name']:<30} malicious={malicious}/{total_eng}  suspicious={suspicious}"
                    if malicious > 0:
                        flag(result_str)
                        add_finding("CRITICAL", "Threat Intel",
                                    f"VirusTotal: {h['name']} flagged by {malicious}/{total_eng} AV engines")
                    elif suspicious > 0:
                        warn(result_str)
                        add_finding("HIGH", "Threat Intel",
                                    f"VirusTotal: {h['name']} flagged as suspicious by {suspicious} engines")
                    else:
                        ok(result_str)

                elif resp.status_code == 404:
                    info(f"{h['name']:<30} not found in VirusTotal database")
                elif resp.status_code == 429:
                    warn("VirusTotal rate limit hit — free tier allows 4 lookups/min")
                    break
                else:
                    warn(f"{h['name']}: VT returned HTTP {resp.status_code}")

            except requests.RequestException as e:
                warn(f"VirusTotal request failed for {h['name']}: {e}")
    elif vt_key:
        info("No process hashes available for VirusTotal lookup")

# ─────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────

def summary():
    section("★", "SUMMARY  —  SEVERITY REPORT")

    order     = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    by_sev    = defaultdict(list)
    for f in FINDINGS:
        by_sev[f["severity"]].append(f)

    total = len(FINDINGS)
    if total == 0:
        ok("No significant findings detected — system appears clean")
        return

    print(f"  Total findings: {bold(str(total))}\n")

    for s in order:
        items = by_sev.get(s, [])
        if not items:
            continue
        fn = SEVERITY_FN.get(s, lambda t: t)
        print(f"  {fn(f'[{s}]')}  {len(items)} finding(s):")
        for item in items:
            print(f"    [{item['category']}] {item['description']}")
        print()

    print(cyan("  " + "─" * 54))

    if by_sev["CRITICAL"]:
        flag(bold("CRITICAL findings present — immediate investigation required"))
    elif by_sev["HIGH"]:
        warn(bold("HIGH severity findings — investigate promptly"))
    elif by_sev["MEDIUM"]:
        info("Medium severity findings — schedule review")
    else:
        ok("No critical or high severity findings detected")

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IR-TRIAGE v1.0 — Cross-platform Incident Response Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python ir_triage.py
  python ir_triage.py --vt-key abc123 --abuse-key xyz789
  python ir_triage.py --skip-hashes --skip-logs
        """
    )
    parser.add_argument("--vt-key",      help="VirusTotal API key (free at virustotal.com)",    default=None)
    parser.add_argument("--abuse-key",   help="AbuseIPDB API key (free at abuseipdb.com)",      default=None)
    parser.add_argument("--skip-hashes", help="Skip process hashing (faster run)",              action="store_true")
    parser.add_argument("--skip-logs",   help="Skip log analysis",                              action="store_true")
    args = parser.parse_args()

    banner()

    module_system_info()
    module_processes()
    external_ips   = module_network()
    module_persistence()

    if not args.skip_logs:
        module_logs()

    process_hashes = {}
    if not args.skip_hashes:
        process_hashes = module_hashes()

    module_threat_intel(
        external_ips,
        process_hashes,
        vt_key=args.vt_key,
        abuse_key=args.abuse_key,
    )

    summary()

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print()
    print(cyan("╔══════════════════════════════════════════════════════╗"))
    print(cyan("║") + f"  Triage complete: {ts}                 " + cyan("║"))
    print(cyan("╚══════════════════════════════════════════════════════╝"))
    print()


if __name__ == "__main__":
    main()
