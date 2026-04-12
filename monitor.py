"""
monitor.py — Real-Time Intrusion Detection System
==================================================
Windows-compatible alternative to Fail2Ban / OSSEC.

HOW IT WORKS:
  1. Watches security.log (written by app.py) in real-time
  2. Counts failed login attempts per IP address
  3. If an IP fails too many times → prints a BLOCK ALERT
  4. Also detects rate limit hits and unauthorized API access

HOW TO RUN:
  Open a SECOND terminal in VS Code and run:
      python monitor.py

Leave it running while you test the app.
"""

import time
import os
import re
from collections import defaultdict
from datetime import datetime

# ============================================================
# CONFIGURATION — adjust these thresholds as needed
# ============================================================
LOG_FILE = 'security.log'           # Must match app.py logging filename
FAILED_LOGIN_THRESHOLD = 5          # Block after this many failures
TIME_WINDOW_SECONDS = 60            # Count failures within this time window (1 minute)
CHECK_INTERVAL = 1                  # How often to check log (seconds)

# ============================================================
# DATA STRUCTURES
# ============================================================
# Stores list of timestamps for each IP's failed logins
failed_attempts = defaultdict(list)

# IPs that have already been flagged (avoid duplicate alerts)
blocked_ips = set()

# ============================================================
# HELPER: Parse a log line and extract event info
# ============================================================
def parse_log_line(line):
    """
    Extracts timestamp, level, event type, and IP from a log line.
    Log format: 2024-01-01 12:00:00,000 - WARNING - LOGIN_FAILED | IP: 127.0.0.1 | User: admin
    Returns a dict or None if line doesn't match.
    """
    # Match the log format from app.py
    pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ - (\w+) - (\w+) \| IP: ([\d\.]+)'
    match = re.search(pattern, line)
    if match:
        return {
            'timestamp': match.group(1),
            'level':     match.group(2),    # INFO, WARNING, ERROR
            'event':     match.group(3),    # LOGIN_FAILED, LOGIN_SUCCESS, etc.
            'ip':        match.group(4),
            'raw':       line.strip()
        }
    return None

# ============================================================
# MAIN: Check for threats based on parsed event
# ============================================================
def check_for_threats(event):
    """Analyze event and print alerts if suspicious behavior detected."""
    ip = event['ip']
    now = datetime.now()

    # --- Threat 1: Multiple Failed Logins (Brute Force) ---
    if event['event'] == 'LOGIN_FAILED':
        # Add current timestamp to this IP's failure list
        failed_attempts[ip].append(now)

        # Remove timestamps older than TIME_WINDOW_SECONDS
        failed_attempts[ip] = [
            t for t in failed_attempts[ip]
            if (now - t).total_seconds() <= TIME_WINDOW_SECONDS
        ]

        count = len(failed_attempts[ip])

        print(f"  ⚠️  Failed login #{count} from IP: {ip}")

        # Trigger block alert if threshold exceeded
        if count >= FAILED_LOGIN_THRESHOLD and ip not in blocked_ips:
            blocked_ips.add(ip)
            print_alert(
                "BRUTE FORCE DETECTED",
                ip,
                f"{count} failed logins in {TIME_WINDOW_SECONDS} seconds",
                "BLOCK THIS IP"
            )

    # --- Threat 2: Rate Limit Hit ---
    elif event['event'] == 'RATE_LIMIT_EXCEEDED':
        print_alert(
            "RATE LIMIT EXCEEDED",
            ip,
            "Too many requests sent",
            "Possible DoS attack or scanner"
        )

    # --- Threat 3: Unauthorized API Access ---
    elif event['event'] == 'UNAUTHORIZED':
        print_alert(
            "UNAUTHORIZED API ACCESS",
            ip,
            "Invalid or missing API key",
            "Possible API enumeration attempt"
        )

    # --- Info: Successful login (good to track) ---
    elif event['event'] == 'LOGIN_SUCCESS':
        # If IP was in blocked list but now succeeds, note it (possible bypass)
        if ip in blocked_ips:
            print(f"  🔴 SUSPICIOUS: Blocked IP {ip} had a successful login!")
        else:
            print(f"  ✅ Successful login from IP: {ip}")

        # Clear failed count on success (they got in legitimately)
        if ip in failed_attempts:
            del failed_attempts[ip]

    # --- Info: New user registered ---
    elif event['event'] == 'NEW_USER_REGISTERED':
        print(f"  👤 New registration from IP: {ip}")

def print_alert(threat_type, ip, detail, action):
    """Print a clearly visible alert box."""
    border = "=" * 55
    print(f"\n{border}")
    print(f"  🚨 ALERT: {threat_type}")
    print(f"  IP Address : {ip}")
    print(f"  Detail     : {detail}")
    print(f"  Action     : {action}")
    print(f"  Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{border}\n")

# ============================================================
# REAL-TIME LOG WATCHER (tail -f equivalent for Windows)
# ============================================================
def tail_log(filepath):
    """
    Generator that yields new lines added to a file.
    Works like Linux 'tail -f' but in pure Python (Windows compatible).
    """
    # Wait for log file to be created if it doesn't exist yet
    while not os.path.exists(filepath):
        print(f"  Waiting for {filepath} to be created... (start app.py first)")
        time.sleep(2)

    with open(filepath, 'r') as f:
        # Move to end of file — only watch NEW lines from this point
        f.seek(0, 2)
        print(f"  📂 Watching: {os.path.abspath(filepath)}\n")

        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(CHECK_INTERVAL)

# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == '__main__':
    print("=" * 55)
    print("  🛡️  INTRUSION DETECTION MONITOR STARTED")
    print(f"  Threshold : {FAILED_LOGIN_THRESHOLD} failures / {TIME_WINDOW_SECONDS}s")
    print("  Status    : ACTIVE — waiting for events...")
    print("=" * 55 + "\n")

    try:
        for line in tail_log(LOG_FILE):
            event = parse_log_line(line)
            if event:
                check_for_threats(event)
    except KeyboardInterrupt:
        print("\n\n  Monitor stopped by user. Goodbye!")
