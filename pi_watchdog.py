#!/usr/bin/env python3
"""
pi_watchdog.py — Security watchdog for Raspberry Pi 4 gateway

Monitors for and responds to:
  • ARP spoofing / cable MITM   — MAC address changes for known IPs
  • Port scan probes             — NULL/XMAS/FIN/SYN probes via iptables LOG
  • DDoS / flood attacks         — SYN, ICMP, UDP flood alerts from iptables
  • SSH brute force              — repeated auth failures from auth.log
  • Bogon / spoofed source IPs  — RFC1918 packets arriving on WAN
  • Service health               — systemd service watchdog
  • Connection-rate anomalies    — hashlimit/connlimit alerts from iptables LOG

Actions:
  • Logs all events to <log_dir>/watchdog.log (+ journald)
  • Optionally auto-blocks offending IPs with iptables (--autoblock true)
  • Blocks expire after --block-expire seconds (default: 86400 = 24 h)
  • Persists blocklist to <log_dir>/blocklist.json across restarts

Usage (run as root via systemd):
  python3 pi_watchdog.py --wan-iface eth0 --lan-iface eth1 \
      --log-dir /opt/chromecast_blocker/logs \
      --autoblock true --block-expire 86400
"""

import argparse
import ctypes
import fcntl
import ipaddress
import json
import logging
import os
import re
import signal
import socket as _socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Thresholds (conservative — tune to your traffic patterns)
# ─────────────────────────────────────────────────────────────────────────────
SCAN_TYPES = {
    "FW-NULLSCAN", "FW-XMASSCAN", "FW-FINSCAN", "FW-SYNRST",
    "FW-FRAGMENT", "FW-INVALID",
}
FLOOD_TYPES = {"FW-SYNFLOOD", "FW-ICMPFLOOD", "FW-UDPFLOOD", "FW-CONNRATE",
               "FW-CONNLIMIT", "FW-FWDRATE"}

# How many scan/flood events within TIME_WINDOW seconds before auto-block
SCAN_THRESHOLD  = 2    # any scan type → block quickly
FLOOD_THRESHOLD = 5
SSH_THRESHOLD   = 4    # failed SSH auths within SSH_WINDOW
SSH_WINDOW      = 120  # seconds
TIME_WINDOW     = 60   # seconds for scan/flood counting

# LAN prefixes that should NEVER be blocked (Pi itself, DHCP range)
NEVER_BLOCK = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.42.0.0/24"),
]


# ─────────────────────────────────────────────────────────────────────────────
# systemd sd_notify helper
# ─────────────────────────────────────────────────────────────────────────────

def sd_notify(msg: str) -> None:
    """Send a state notification to systemd via $NOTIFY_SOCKET (no-op if absent)."""
    sock_path = os.environ.get("NOTIFY_SOCKET", "")
    if not sock_path:
        return
    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM) as sock:
            # Abstract socket namespace uses a leading null byte
            addr = "\0" + sock_path[1:] if sock_path.startswith("@") else sock_path
            sock.connect(addr)
            sock.sendall(msg.encode())
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Log enrichment helpers
# ─────────────────────────────────────────────────────────────────────────────

# Module-level rDNS cache: ip → (hostname, cache_timestamp)
_rdns_cache: dict = {}
_RDNS_TTL   = 3600   # seconds before a cached lookup expires


def new_eid() -> str:
    """Return a short 8-char hex event ID for cross-log correlation."""
    return uuid.uuid4().hex[:8]


def iptables_fields(line: str) -> dict:
    """
    Parse all KEY=VALUE pairs from an iptables LOG line.
    Returns a dict with keys like IN, OUT, SRC, DST, PROTO, SPT, DPT,
    MAC, LEN, TTL, ID, DF, WINDOW, etc.
    """
    return dict(re.findall(r"(\w+)=([^\s]*)", line))


def rdns_lookup(ip: str, timeout: float = 1.5) -> str:
    """
    Reverse-DNS with a 1-hour in-process cache and 1.5s timeout.
    Returns the hostname, or the IP itself when lookup fails/times out.
    """
    now = time.time()
    if ip in _rdns_cache:
        hostname, ts = _rdns_cache[ip]
        if now - ts < _RDNS_TTL:
            return hostname

    result = [ip]

    def _lookup():
        try:
            result[0] = _socket.gethostbyaddr(ip)[0]
        except OSError:
            pass

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout)
    _rdns_cache[ip] = (result[0], now)
    return result[0]


# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────────────────

def setup_logger(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "watchdog.log"

    logger = logging.getLogger("watchdog")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # intrusions.log — WARNING and above only; easy to tail for a quick threat view
    ih = logging.FileHandler(log_dir / "intrusions.log")
    ih.setLevel(logging.WARNING)
    ih.setFormatter(fmt)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ih)
    logger.addHandler(sh)
    return logger


# ─────────────────────────────────────────────────────────────────────────────
# IP blocker — manages iptables rules + expiry
# ─────────────────────────────────────────────────────────────────────────────

class IPBlocker:
    """Thread-safe iptables block manager with auto-expiry."""

    def __init__(self, log_dir: Path, expire_secs: int, autoblock: bool,
                 logger: logging.Logger):
        self._lock      = threading.Lock()
        self._blocked   = {}           # ip_str → expiry_timestamp
        self._json_path = log_dir / "blocklist.json"
        self._expire    = expire_secs
        self._autoblock = autoblock
        self._log       = logger
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self):
        if self._json_path.exists():
            try:
                data = json.loads(self._json_path.read_text())
                now  = time.time()
                self._blocked = {
                    ip: ts for ip, ts in data.items() if ts > now
                }
                if self._blocked:
                    self._log.info(
                        "[Blocklist] Loaded %d persistent blocks", len(self._blocked)
                    )
            except (json.JSONDecodeError, ValueError):
                self._blocked = {}

    def _save(self):
        try:
            self._json_path.write_text(json.dumps(self._blocked, indent=2))
        except OSError as exc:
            self._log.warning("[Blocklist] Could not save: %s", exc)

    # ── Public API ────────────────────────────────────────────────────────

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked and self._blocked[ip] > time.time()

    def block(self, ip: str, reason: str):
        """Block an IP (log only if autoblock=False)."""
        if self._is_safe_ip(ip):
            self._log.debug("[Blocker] Skipping safe IP %s (%s)", ip, reason)
            return

        with self._lock:
            if ip in self._blocked and self._blocked[ip] > time.time():
                return  # already blocked

            expiry     = time.time() + self._expire
            self._blocked[ip] = expiry
            expires_at = datetime.fromtimestamp(expiry).strftime("%Y-%m-%d %H:%M:%S")
            eid        = new_eid()
            rdns       = rdns_lookup(ip)

            if self._autoblock:
                self._iptables_block(ip)
                self._log.warning(
                    "[BLOCKED] eid=%s src=%s rdns=%s reason=%r expires=%s action=iptables-DROP",
                    eid, ip, rdns, reason, expires_at,
                )
            else:
                self._log.warning(
                    "[ALERT] eid=%s src=%s rdns=%s reason=%r expires=%s action=log-only",
                    eid, ip, rdns, reason, expires_at,
                )
            self._save()

    def expire_blocks(self):
        """Remove expired blocks from iptables and the blocklist."""
        now = time.time()
        with self._lock:
            expired = [ip for ip, ts in self._blocked.items() if ts <= now]
            for ip in expired:
                del self._blocked[ip]
                if self._autoblock:
                    self._iptables_unblock(ip)
                    self._log.info("[Unblocked] %s — block expired", ip)
            if expired:
                self._save()

    def status(self) -> list:
        now = time.time()
        with self._lock:
            return [
                {"ip": ip, "expires_in": int(ts - now)}
                for ip, ts in self._blocked.items()
                if ts > now
            ]

    # ── Internal helpers ─────────────────────────────────────────────────

    def _is_safe_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in NEVER_BLOCK)
        except ValueError:
            return True  # malformed — don't block

    @staticmethod
    def _run(cmd: list):
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            pass  # rule may already exist; silently ignore

    def _iptables_block(self, ip: str):
        self._run(["iptables", "-I", "INPUT", "1",
                   "-s", ip, "-j", "DROP",
                   "-m", "comment", "--comment", f"watchdog-block:{ip}"])

    def _iptables_unblock(self, ip: str):
        self._run(["iptables", "-D", "INPUT",
                   "-s", ip, "-j", "DROP",
                   "-m", "comment", "--comment", f"watchdog-block:{ip}"])


# ─────────────────────────────────────────────────────────────────────────────
# ARP Monitor — detects cable MITM / ARP spoofing
# ─────────────────────────────────────────────────────────────────────────────

class ARPMonitor(threading.Thread):
    """
    Polls /proc/net/arp every 5 seconds.
    Alerts when a known IP changes its MAC address (classic ARP poisoning sign).
    """

    ARP_RE = re.compile(
        r"^([\d.]+)\s+0x\w+\s+0x(\w+)\s+([0-9a-f:]+)\s+\S+\s+(\S+)",
        re.MULTILINE,
    )
    POLL_INTERVAL = 5  # seconds

    def __init__(self, blocker: IPBlocker, logger: logging.Logger):
        super().__init__(name="arp-monitor", daemon=True)
        self._blocker  = blocker
        self._log      = logger
        self._known    = {}   # ip → mac
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        self._log.info("[ARP] Monitor started (poll every %ds)", self.POLL_INTERVAL)
        while not self._stop_evt.wait(self.POLL_INTERVAL):
            self._check()

    def _check(self):
        try:
            raw = Path("/proc/net/arp").read_text()
        except OSError:
            return

        for match in self.ARP_RE.finditer(raw):
            ip, flags_hex, mac, iface = match.groups()
            flags = int(flags_hex, 16)
            if flags == 0:
                continue  # incomplete entry (no reply received yet)
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue  # broadcast / unresolved

            if ip in self._known:
                if self._known[ip] != mac:
                    eid = new_eid()
                    self._log.critical(
                        "[ARP-SPOOF] eid=%s ip=%s iface=%s old_mac=%s new_mac=%s "
                        "— possible cable MITM / ARP poisoning! "
                        "Verify physical access to switch/cables.",
                        eid, ip, iface, self._known[ip], mac,
                    )
                    # Don't auto-block — spoofed IP may be the legitimate gateway.
                    # Physical inspection of cabling is required to trace this attack.
            else:
                self._log.debug("[ARP] Learned %s → %s on %s", ip, mac, iface)
            self._known[ip] = mac


# ─────────────────────────────────────────────────────────────────────────────
# Kernel / iptables LOG monitor
# ─────────────────────────────────────────────────────────────────────────────

class KernelLogMonitor(threading.Thread):
    """
    Follows kernel log via 'journalctl -f -k' and parses iptables LOG lines.
    Tracks event counts per IP and triggers blocks on threshold breach.
    """

    # Matches lines like: FW-NULLSCAN: IN=eth0 OUT= SRC=1.2.3.4 DST=...
    FW_RE = re.compile(r"(FW-[A-Z_]+):[^S]*SRC=([\d.]+)")

    def __init__(self, blocker: IPBlocker, logger: logging.Logger):
        super().__init__(name="kern-log-monitor", daemon=True)
        self._blocker   = blocker
        self._log       = logger
        self._stop_evt  = threading.Event()
        # ip → deque of (event_type, timestamp) within sliding window
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        self._log.info("[KernLog] Monitor started (journalctl -f -k)")
        try:
            proc = subprocess.Popen(
                ["journalctl", "-f", "-k", "--output=short-monotonic",
                 "--no-hostname"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except FileNotFoundError:
            self._log.warning("[KernLog] journalctl not found — falling back to /var/log/kern.log")
            self._tail_file("/var/log/kern.log")
            return

        try:
            for line in iter(proc.stdout.readline, ""):
                if self._stop_evt.is_set():
                    break
                self._parse_line(line.rstrip())
        finally:
            proc.terminate()

    def _tail_file(self, path: str):
        """Fallback: tail a log file when journalctl is unavailable."""
        try:
            proc = subprocess.Popen(
                ["tail", "-F", "-n", "0", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in iter(proc.stdout.readline, ""):
                if self._stop_evt.is_set():
                    break
                self._parse_line(line.rstrip())
        except FileNotFoundError:
            self._log.error("[KernLog] %s not found — iptables log monitoring disabled", path)

    def _parse_line(self, line: str):
        m = self.FW_RE.search(line)
        if not m:
            return
        event_type, src_ip = m.group(1), m.group(2)

        # Parse every KEY=VALUE field the iptables LOG target recorded
        f    = iptables_fields(line)
        eid  = new_eid()
        rdns = rdns_lookup(src_ip)
        mac  = f.get("MAC", "")
        # iptables MAC field is formatted as "dst:src:type" — keep src MAC (bytes 7-12)
        src_mac = mac.split(":", 6)[6].rsplit(":", 1)[0] if mac.count(":") >= 7 else mac

        self._log.warning(
            "[ATTACK] eid=%s src=%s rdns=%s type=%s proto=%s "
            "spt=%s dpt=%s dst=%s in=%s mac=%s ttl=%s len=%s",
            eid, src_ip, rdns, event_type,
            f.get("PROTO", "?"), f.get("SPT", "?"), f.get("DPT", "?"),
            f.get("DST",   "?"), f.get("IN",   "?"),
            src_mac or "?",
            f.get("TTL",   "?"), f.get("LEN",  "?"),
        )

        with self._lock:
            now = time.time()
            dq  = self._events[src_ip]
            dq.append((event_type, now))
            # Evict old events outside the sliding window
            while dq and now - dq[0][1] > TIME_WINDOW:
                dq.popleft()

            scan_count  = sum(1 for e, _ in dq if e in SCAN_TYPES)
            flood_count = sum(1 for e, _ in dq if e in FLOOD_TYPES)

        if scan_count >= SCAN_THRESHOLD:
            self._blocker.block(
                src_ip,
                f"port scan ({scan_count} scan events in {TIME_WINDOW}s)"
            )
        elif flood_count >= FLOOD_THRESHOLD:
            self._blocker.block(
                src_ip,
                f"flood/DDoS ({flood_count} flood events in {TIME_WINDOW}s)"
            )


# ─────────────────────────────────────────────────────────────────────────────
# SSH / Auth log monitor — brute force detection
# ─────────────────────────────────────────────────────────────────────────────

class AuthLogMonitor(threading.Thread):
    """
    Follows SSH auth log via journalctl and counts failed attempts per IP.
    Auto-blocks IPs exceeding SSH_THRESHOLD failures within SSH_WINDOW seconds.
    """

    # Broad trigger — any of these phrases signals an auth failure
    SSH_FAIL_RE = re.compile(
        r"Failed (?:password|publickey)|"
        r"Invalid user|"
        r"(?:Disconnected|Connection closed) from (?:invalid|authenticating) user"
    )
    # Specific field extractors applied after the trigger matches
    _SRC_RE  = re.compile(r" from ([\d.]+)| ([\d.]+) port")
    _USER_RE = re.compile(r"for (?:invalid user )?(\S+) from|Invalid user (\S+) from")
    _PORT_RE = re.compile(r"port (\d+)")
    _METH_RE = re.compile(r"Failed (password|publickey)")

    def __init__(self, blocker: IPBlocker, logger: logging.Logger):
        super().__init__(name="auth-log-monitor", daemon=True)
        self._blocker  = blocker
        self._log      = logger
        self._stop_evt = threading.Event()
        self._fails: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        self._log.info("[Auth] SSH brute-force monitor started")
        try:
            proc = subprocess.Popen(
                ["journalctl", "-f", "-u", "ssh", "-u", "sshd",
                 "--output=short-monotonic", "--no-hostname"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except FileNotFoundError:
            self._tail_file("/var/log/auth.log")
            return

        try:
            for line in iter(proc.stdout.readline, ""):
                if self._stop_evt.is_set():
                    break
                self._parse_line(line.rstrip())
        finally:
            proc.terminate()

    def _tail_file(self, path: str):
        try:
            proc = subprocess.Popen(
                ["tail", "-F", "-n", "0", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in iter(proc.stdout.readline, ""):
                if self._stop_evt.is_set():
                    break
                self._parse_line(line.rstrip())
        except FileNotFoundError:
            self._log.error("[Auth] auth.log not found — SSH brute-force monitoring disabled")

    def _parse_line(self, line: str):
        if not self.SSH_FAIL_RE.search(line):
            return

        ip_m = self._SRC_RE.search(line)
        if not ip_m:
            return
        src_ip = ip_m.group(1) or ip_m.group(2)
        if not src_ip:
            return

        user_m = self._USER_RE.search(line)
        user   = next((g for g in (user_m.groups() if user_m else ()) if g), "?")
        port_m = self._PORT_RE.search(line)
        port   = port_m.group(1) if port_m else "?"
        meth_m = self._METH_RE.search(line)
        method = meth_m.group(1) if meth_m else "?"

        with self._lock:
            now = time.time()
            dq  = self._fails[src_ip]
            dq.append(now)
            while dq and now - dq[0] > SSH_WINDOW:
                dq.popleft()
            count = len(dq)

        rdns = rdns_lookup(src_ip)
        eid  = new_eid()

        self._log.warning(
            "[SSH-FAIL] eid=%s src=%s rdns=%s user=%s method=%s port=%s attempt=%d/%d",
            eid, src_ip, rdns, user, method, port, count, SSH_THRESHOLD,
        )

        if count >= SSH_THRESHOLD:
            self._blocker.block(
                src_ip,
                f"SSH brute force ({count} failures in {SSH_WINDOW}s, user={user})"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Service health monitor
# ─────────────────────────────────────────────────────────────────────────────

class ServiceMonitor(threading.Thread):
    """Checks that critical systemd services stay active. Logs if any crash."""

    SERVICES = [
        "chromecast-blocker",
        "chromecast-ui",
        "fail2ban",
        "dnsmasq",
        "arpwatch",
        "arpwatch-lan",
    ]
    POLL_INTERVAL = 60  # seconds

    def __init__(self, logger: logging.Logger):
        super().__init__(name="service-monitor", daemon=True)
        self._log      = logger
        self._stop_evt = threading.Event()
        self._prev_states: dict[str, str] = {}

    def stop(self):
        self._stop_evt.set()

    def run(self):
        self._log.info("[Services] Health monitor started (poll every %ds)", self.POLL_INTERVAL)
        while not self._stop_evt.wait(self.POLL_INTERVAL):
            self._check()

    def _check(self):
        for svc in self.SERVICES:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "--quiet", svc],
                    capture_output=True,
                )
                state = "active" if result.returncode == 0 else "failed"
            except FileNotFoundError:
                state = "unknown"

            prev = self._prev_states.get(svc)
            if prev is not None and prev != state:
                if state == "failed":
                    self._log.error("[Service] %s changed state: %s → %s", svc, prev, state)
                else:
                    self._log.info("[Service] %s recovered: %s → %s", svc, prev, state)
            elif prev is None and state == "failed":
                self._log.error("[Service] %s is not running", svc)

            self._prev_states[svc] = state


# ─────────────────────────────────────────────────────────────────────────────
# Block expiry manager
# ─────────────────────────────────────────────────────────────────────────────

class ExpiryManager(threading.Thread):
    """Periodically removes expired IP blocks."""

    def __init__(self, blocker: IPBlocker, logger: logging.Logger):
        super().__init__(name="expiry-manager", daemon=True)
        self._blocker  = blocker
        self._log      = logger
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        while not self._stop_evt.wait(300):   # check every 5 minutes
            self._blocker.expire_blocks()
            active = self._blocker.status()
            if active:
                self._log.debug(
                    "[Expiry] %d active block(s): %s",
                    len(active),
                    ", ".join(e["ip"] for e in active),
                )


# ─────────────────────────────────────────────────────────────────────────────
# Status reporter — periodic summary to log
# ─────────────────────────────────────────────────────────────────────────────

class StatusReporter(threading.Thread):
    """Writes a periodic status line to the watchdog log."""

    def __init__(self, blocker: IPBlocker, logger: logging.Logger):
        super().__init__(name="status-reporter", daemon=True)
        self._blocker  = blocker
        self._log      = logger
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        while not self._stop_evt.wait(600):   # every 10 minutes
            blocked = self._blocker.status()
            self._log.info(
                "[Status] Watchdog alive — %d IP(s) currently blocked",
                len(blocked),
            )
            for entry in blocked:
                self._log.info(
                    "[Status]   %s  (expires in %ds)",
                    entry["ip"], entry["expires_in"]
                )


# ─────────────────────────────────────────────────────────────────────────────
# Hardware Watchdog — BCM2835 / BCM2711 built-in WDT (/dev/watchdog)
# ─────────────────────────────────────────────────────────────────────────────
# Notification Manager — alert user via wall, alert file, and journal
# ─────────────────────────────────────────────────────────────────────────────

class NotificationManager:
    """
    Delivers security alerts to:
      • All logged-in terminal users  (via `wall`)
      • A JSON alert file that the web UI polls every 5 s
      • A FATAL_ALERT flat file that other scripts can watch
      • The systemd journal (already handled by the caller's logger)
    """

    ALERT_FILE  = Path("/opt/chromecast_blocker/logs/ai_alerts.json")
    FATAL_FILE  = Path("/opt/chromecast_blocker/logs/FATAL_ALERT")
    MAX_ALERTS  = 200   # keep only last N alerts in the JSON file

    def __init__(self, logger: logging.Logger):
        self._log    = logger
        self._alerts: list = []
        self._lock   = threading.Lock()
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self):
        if self.ALERT_FILE.exists():
            try:
                self._alerts = json.loads(self.ALERT_FILE.read_text())
            except Exception:
                self._alerts = []

    def _save(self):
        try:
            self.ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.ALERT_FILE.write_text(
                json.dumps(self._alerts[-self.MAX_ALERTS:], indent=2)
            )
        except OSError as exc:
            self._log.warning("[Notify] Could not write alert file: %s", exc)

    # ── Public API ────────────────────────────────────────────────────────

    def notify(self, level: str, summary: str, details: str,
               eid: Optional[str] = None):
        """
        Emit a security notification at the given level.
        level: SUSPICIOUS | CRITICAL | FATAL
        """
        eid = eid or new_eid()
        ts  = datetime.now().isoformat(timespec="seconds")

        alert = {
            "eid":     eid,
            "ts":      ts,
            "level":   level,
            "summary": summary,
            "details": details,
        }

        with self._lock:
            self._alerts.append(alert)
            self._save()

        # Broadcast to every logged-in terminal session
        border  = "=" * 62
        wall_msg = (
            f"\n\n{border}\n"
            f"  [AI-WATCHDOG]  {level}\n"
            f"  {summary}\n"
            f"  {details}\n"
            f"{border}\n"
        )
        try:
            subprocess.run(["wall", wall_msg], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # FATAL: write a persistent marker file
        if level == "FATAL":
            try:
                self.FATAL_FILE.parent.mkdir(parents=True, exist_ok=True)
                self.FATAL_FILE.write_text(
                    f"FATAL ALERT at {ts}\n"
                    f"eid={eid}\n"
                    f"{summary}\n\n"
                    f"{details}\n"
                )
            except OSError:
                pass

    def get_recent(self, n: int = 50) -> list:
        """Return the last n alerts (for web UI polling)."""
        with self._lock:
            return list(self._alerts[-n:])


# ─────────────────────────────────────────────────────────────────────────────
# Emergency Shutdown — stop all forwarding and disconnect from WAN
# ─────────────────────────────────────────────────────────────────────────────

class EmergencyShutdown:
    """
    Hard stop invoked only for FATAL threat level.

    What it does (in order):
      1. Set iptables FORWARD default policy to DROP  (all transit traffic stops)
      2. Flush FORWARD chain                           (remove any lingering ACCEPT rules)
      3. Flush NAT POSTROUTING                         (MASQUERADE gone — WAN dead for clients)
      4. Same for IPv6
      5. Disable kernel IP forwarding via sysctl
      6. Bring the WAN interface down                  (hard disconnect from internet)
      7. Write a LOCKDOWN_ACTIVE marker file

    Local SSH access via the LAN interface is preserved throughout
    (INPUT chain is not touched).

    To restore:
        sudo python3 pi_watchdog.py --clear-lockdown
    """

    LOCKDOWN_MARKER = Path("/opt/chromecast_blocker/logs/LOCKDOWN_ACTIVE")

    def __init__(self, wan_iface: str, lan_iface: str, logger: logging.Logger):
        self._wan       = wan_iface
        self._lan       = lan_iface
        self._log       = logger
        self._executed  = False
        self._lock      = threading.Lock()

    @staticmethod
    def _run(cmd: list):
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                FileNotFoundError):
            pass

    def execute(self, reason: str):
        with self._lock:
            if self._executed:
                return
            self._executed = True

        self._log.critical(
            "[EMERGENCY] FATAL threat detected — initiating lockdown. Reason: %s",
            reason,
        )

        # 1 & 2 — Drop and flush FORWARD (IPv4)
        self._run(["iptables", "-P", "FORWARD", "DROP"])
        self._run(["iptables", "-F", "FORWARD"])
        # 3 — Remove NAT masquerade
        self._run(["iptables", "-t", "nat", "-F", "POSTROUTING"])
        # 4 — IPv6 FORWARD
        self._run(["ip6tables", "-P", "FORWARD", "DROP"])
        self._run(["ip6tables", "-F", "FORWARD"])
        # 5 — Disable kernel forwarding entirely
        self._run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
        self._run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"])
        # 6 — Bring WAN interface down
        self._run(["ip", "link", "set", self._wan, "down"])

        # 7 — Write persistent lockdown marker
        ts = datetime.now().isoformat(timespec="seconds")
        try:
            self.LOCKDOWN_MARKER.parent.mkdir(parents=True, exist_ok=True)
            self.LOCKDOWN_MARKER.write_text(
                f"LOCKDOWN at {ts}\n"
                f"Reason: {reason}\n"
                f"WAN interface {self._wan!r} brought down.\n"
                f"To restore: sudo python3 pi_watchdog.py --clear-lockdown\n"
            )
        except OSError:
            pass

        self._log.critical(
            "[EMERGENCY] Lockdown complete — "
            "FORWARD=DROP, NAT flushed, %s DOWN. "
            "Restore with: sudo python3 pi_watchdog.py --clear-lockdown",
            self._wan,
        )
        sd_notify("STOPPING=1")
        sd_notify(f"STATUS=LOCKDOWN: {reason}")

    @classmethod
    def clear(cls, wan_iface: str, logger: logging.Logger):
        """Reverse a lockdown and restore normal gateway operation."""
        logger.info("[EMERGENCY] Clearing lockdown — restoring gateway operation")
        for cmd in [
            ["iptables", "-P", "FORWARD", "ACCEPT"],
            ["ip6tables", "-P", "FORWARD", "ACCEPT"],
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
            ["ip", "link", "set", wan_iface, "up"],
        ]:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        if cls.LOCKDOWN_MARKER.exists():
            cls.LOCKDOWN_MARKER.unlink(missing_ok=True)
        logger.info("[EMERGENCY] Lockdown cleared. Re-enable MASQUERADE manually if needed.")


# ─────────────────────────────────────────────────────────────────────────────
# Threat-scoring tables used by AIAnalyser
# ─────────────────────────────────────────────────────────────────────────────

# Base score added per event of the given type
THREAT_SCORE_MAP: dict[str, int] = {
    "ARP-SPOOF":    8,   # strong indicator of physical/cable MITM
    "FW-NULLSCAN":  3,   # stealth TCP scan variants
    "FW-XMASSCAN":  3,
    "FW-FINSCAN":   3,
    "FW-SYNRST":    2,
    "FW-INVALID":   1,
    "FW-FRAGMENT":  1,
    "FW-SYNFLOOD":  4,   # active DoS / DDoS
    "FW-ICMPFLOOD": 3,
    "FW-UDPFLOOD":  3,
    "FW-CONNRATE":  3,
    "FW-CONNLIMIT": 2,
    "FW-FWDRATE":   3,
    "SSH-FAIL":     2,   # per individual failure event
    "BLOCKED":      0,   # already handled — no extra score
    "ATTACK":       1,   # generic fallback category
}

# (min_score, max_score) → level
THREAT_LEVEL_THRESHOLDS: list[tuple[int, int, str]] = [
    (0,  2,  "NORMAL"),
    (3,  5,  "SUSPICIOUS"),
    (6,  9,  "CRITICAL"),
    (10, 9999, "FATAL"),
]


# ─────────────────────────────────────────────────────────────────────────────
# AI Analyser — threat correlation + optional LLM-assisted classification
# ─────────────────────────────────────────────────────────────────────────────

class AIAnalyser(threading.Thread):
    """
    Runs every `poll_interval` seconds and does two things:

    1. Rule-based threat scoring
       ─ Parses the last LOG_TAIL_LINES lines from watchdog.log.
       ─ Maps each event type to a base threat score (THREAT_SCORE_MAP).
       ─ Awards a coordination bonus (+3) when the same source IP
         appears in ≥ 3 different attack categories simultaneously.
       ─ Derives an overall threat level:
           NORMAL (0–2) / SUSPICIOUS (3–5) / CRITICAL (6–9) / FATAL (≥10)
       ─ De-duplicates events by eid so only new events raise the score.

    2. Optional LLM-assisted classification (ollama or compatible API)
       ─ When --llm-endpoint is set AND the rule-based level is ≥ SUSPICIOUS,
         the last 20 new events are sent to the model as a concise excerpt.
       ─ The model is asked to classify the threat as
         NORMAL / SUSPICIOUS / CRITICAL / FATAL and reply in JSON.
       ─ If the model's verdict is *higher* than the rule-based score,
         the level is upgraded.  It can never downgrade a score.
       ─ Falls back silently to rule-based if the endpoint is unreachable.

    Escalation:
       SUSPICIOUS  → notify user (wall + alert file)
       CRITICAL    → notify user
       FATAL       → notify user + call EmergencyShutdown.execute()
    """

    LOG_TAIL_LINES = 200
    LOG_LINE_RE    = re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
        r"\s+\[(?P<level>[A-Z]+)\]"
        r"\s+\[(?P<cat>[^\]]+)\]"
        r"\s+(?P<body>.+)$"
    )
    KV_RE = re.compile(r"(\w+)=([^\s]+)")

    def __init__(
        self,
        log_dir:       Path,
        notifier:      NotificationManager,
        shutdown:      EmergencyShutdown,
        logger:        logging.Logger,
        poll_interval: int  = 30,
        llm_endpoint:  Optional[str] = None,
        llm_model:     str  = "phi3:mini",
    ):
        super().__init__(name="ai-analyser", daemon=True)
        self._log_dir   = log_dir
        self._notifier  = notifier
        self._shutdown  = shutdown
        self._log       = logger
        self._interval  = poll_interval
        self._llm_url   = llm_endpoint
        self._llm_model = llm_model
        self._stop_evt  = threading.Event()
        # eids already escalated — prevents duplicate alerts across cycles
        self._seen_eids: set = set()
        self._last_level    = "NORMAL"

    def stop(self):
        self._stop_evt.set()

    def run(self):
        self._log.info(
            "[AI] Analyser started — poll=%ds  llm=%s  model=%s",
            self._interval,
            self._llm_url or "disabled (rule-based only)",
            self._llm_model,
        )
        while not self._stop_evt.wait(self._interval):
            try:
                self._analyse()
            except Exception as exc:
                self._log.error("[AI] Analysis cycle error: %s", exc, exc_info=True)

    # ── Core analysis cycle ───────────────────────────────────────────────

    def _analyse(self):
        lines = self._tail_log(self._log_dir / "watchdog.log", self.LOG_TAIL_LINES)
        if not lines:
            return

        events = self._parse_events(lines)
        if not events:
            return

        # Filter to only events we have not already scored
        new_events = []
        for ev in events:
            eid = ev.get("eid", "")
            if eid and eid in self._seen_eids:
                continue
            if eid:
                self._seen_eids.add(eid)
                # Keep the set bounded to avoid unbounded memory growth
                if len(self._seen_eids) > 5_000:
                    self._seen_eids = set(list(self._seen_eids)[-2_000:])
            new_events.append(ev)

        if not new_events:
            return

        # Per-IP threat scoring
        ip_scores: dict = defaultdict(int)
        ip_types:  dict = defaultdict(set)

        for ev in new_events:
            cat   = ev.get("cat", "")
            src   = ev.get("src", "")
            etype = ev.get("type", "") or cat
            score = THREAT_SCORE_MAP.get(etype, 0) or THREAT_SCORE_MAP.get(cat, 0)
            if score > 0 and src:
                ip_scores[src] += score
                ip_types[src].add(etype or cat)

        if not ip_scores:
            return

        # Coordination bonus: same source in ≥3 distinct attack categories
        for ip, types in ip_types.items():
            if len(types) >= 3:
                ip_scores[ip] += 3
                self._log.warning(
                    "[AI] Coordinated multi-vector attack from %s: %s (+3 coordination bonus)",
                    ip, ", ".join(sorted(types)),
                )

        max_score = max(ip_scores.values())
        top_ip    = max(ip_scores, key=lambda k: ip_scores[k])
        level     = self._score_to_level(max_score)

        # Optional LLM upgrade — never downgrades a score
        if level in ("SUSPICIOUS", "CRITICAL") and self._llm_url:
            llm_level = self._ask_llm(new_events[-20:])
            if llm_level and self._level_rank(llm_level) > self._level_rank(level):
                self._log.info(
                    "[AI] LLM upgraded threat level %s → %s", level, llm_level
                )
                level = llm_level

        self._log.info(
            "[AI] Cycle — new_events=%d  top_ip=%s  score=%d  level=%s",
            len(new_events), top_ip, max_score, level,
        )

        if level == "NORMAL" and self._last_level == "NORMAL":
            return

        self._escalate(level, top_ip, max_score, ip_scores, ip_types, new_events)
        self._last_level = level

    # ── Escalation ────────────────────────────────────────────────────────

    def _escalate(
        self, level: str, top_ip: str, score: int,
        ip_scores: dict, ip_types: dict, events: list
    ):
        if level == "NORMAL":
            if self._last_level != "NORMAL":
                self._log.info("[AI] Threat level returned to NORMAL")
            return

        eid          = new_eid()
        attacked_ips = sorted(ip_scores, key=lambda k: ip_scores[k], reverse=True)[:3]
        attack_list  = "; ".join(
            f"{ip} score={ip_scores[ip]} types=[{','.join(sorted(ip_types[ip]))}]"
            for ip in attacked_ips
        )
        summary = f"{level} threat — score={score} — primary source: {top_ip}"
        details = (
            f"Top attackers: {attack_list}\n"
            f"New events this cycle: {len(events)}\n"
            f"Event ID: {eid}"
        )

        self._notifier.notify(level, summary, details, eid)

        if level == "FATAL":
            self._shutdown.execute(
                f"AI FATAL: score={score} from {top_ip} — {attack_list[:120]}"
            )

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _score_to_level(score: int) -> str:
        for lo, hi, lvl in THREAT_LEVEL_THRESHOLDS:
            if lo <= score <= hi:
                return lvl
        return "NORMAL"

    @staticmethod
    def _level_rank(level: str) -> int:
        return {"NORMAL": 0, "SUSPICIOUS": 1, "CRITICAL": 2, "FATAL": 3}.get(level, 0)

    def _tail_log(self, path: Path, n: int) -> list:
        if not path.exists():
            return []
        try:
            result = subprocess.run(
                ["tail", "-n", str(n), str(path)],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout.splitlines()
        except (subprocess.TimeoutExpired, OSError):
            return []

    def _parse_events(self, lines: list) -> list:
        events = []
        for line in lines:
            m = self.LOG_LINE_RE.match(line)
            if not m:
                continue
            ev = {
                "ts":    m.group("ts"),
                "level": m.group("level"),
                "cat":   m.group("cat"),
            }
            for km in self.KV_RE.finditer(m.group("body")):
                ev[km.group(1)] = km.group(2).strip("'\"")
            events.append(ev)
        return events

    # ── Optional LLM call (ollama-compatible API) ─────────────────────────

    def _ask_llm(self, events: list) -> Optional[str]:
        """
        POST the last N event lines to a local LLM (ollama or compatible).
        Expects a JSON response: {"level": "CRITICAL", "reason": "..."}
        Returns the level string, or None on any failure.
        """
        import urllib.request
        import urllib.error

        excerpt = "\n".join(
            f"[{e.get('ts','')}] [{e.get('cat','')}] "
            f"src={e.get('src','?')} type={e.get('type','?')} rdns={e.get('rdns','?')}"
            for e in events
        )
        prompt = (
            "You are a network security analyst on a Raspberry Pi gateway.\n"
            "Analyse the log events below and classify the OVERALL threat level "
            "as exactly one of: NORMAL, SUSPICIOUS, CRITICAL, FATAL.\n"
            "Consider: ARP spoofing=very severe; coordinated multi-vector attacks=severe; "
            "lone port scan=moderate; lone SSH fail=low.\n"
            "Reply with valid JSON only, example: "
            '{"level": "CRITICAL", "reason": "coordinated ARP spoof + port scan"}\n\n'
            f"Events:\n{excerpt}"
        )
        payload = json.dumps({
            "model":   self._llm_model,
            "prompt":  prompt,
            "stream":  False,
            "options": {"temperature": 0, "num_predict": 120},
        }).encode()

        url = self._llm_url.rstrip("/") + "/api/generate"
        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                text = data.get("response", "")
                jm   = re.search(r'\{[^}]+\}', text)
                if jm:
                    result  = json.loads(jm.group())
                    lvl     = str(result.get("level", "")).strip().upper()
                    reason  = result.get("reason", "")
                    if lvl in ("NORMAL", "SUSPICIOUS", "CRITICAL", "FATAL"):
                        self._log.info(
                            "[AI] LLM verdict: level=%s reason=%r", lvl, reason
                        )
                        return lvl
        except (OSError, json.JSONDecodeError, Exception) as exc:
            self._log.debug("[AI] LLM call failed (endpoint=%s): %s", url, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────

class HardwareWatchdog(threading.Thread):
    """
    Arms and continuously pets the Raspberry Pi's built-in hardware watchdog
    (/dev/watchdog, driven by the bcm2835_wdt kernel module).

    Behaviour:
      • Opens /dev/watchdog on start → WDT is armed immediately.
      • Writes a keep-alive byte every PET_INTERVAL seconds.
      • Also calls sd_notify("WATCHDOG=1") so systemd WatchdogSec= is satisfied.
      • Clean shutdown (stop()): writes magic 'V' to disarm → no spurious reboot.
      • Crash / kill -9:  WDT countdown expires → Pi hard-resets automatically.

    Requires (done by harden_pi.sh):
      • dtparam=watchdog=on  in /boot/firmware/config.txt
      • bcm2835_wdt in /etc/modules
    """

    WDT_PATH     = "/dev/watchdog"
    PET_INTERVAL = 10   # seconds — must stay below HW_TIMEOUT
    HW_TIMEOUT   = 15   # seconds to request from the driver

    # linux/watchdog.h  ─  WDIOC_SETTIMEOUT = _IOWR('W', 6, int)
    WDIOC_SETTIMEOUT = 0xC0045706

    def __init__(self, logger: logging.Logger):
        super().__init__(name="hw-watchdog", daemon=True)
        self._log      = logger
        self._stop_evt = threading.Event()
        self._fd       = None
        self._lock     = threading.Lock()   # guards self._fd

    # ── Public API ────────────────────────────────────────────────────────

    def stop(self):
        """Disarm the hardware WDT cleanly ('V' magic close) then stop."""
        self._stop_evt.set()
        with self._lock:
            self._disarm()

    # ── Internal ─────────────────────────────────────────────────────────

    def _open(self) -> bool:
        """Open /dev/watchdog and request HW_TIMEOUT. Returns True on success."""
        try:
            self._fd = open(self.WDT_PATH, "wb", buffering=0)
            actual   = self._set_hw_timeout(self.HW_TIMEOUT)
            self._log.info(
                "[HWDog] /dev/watchdog armed — hw_timeout=%ds  pet_interval=%ds",
                actual, self.PET_INTERVAL,
            )
            return True
        except PermissionError:
            self._log.error(
                "[HWDog] Permission denied on %s — watchdog must run as root",
                self.WDT_PATH,
            )
        except FileNotFoundError:
            self._log.warning(
                "[HWDog] %s not found.\n"
                "        Enable with:  dtparam=watchdog=on  in /boot/firmware/config.txt\n"
                "        then:         modprobe bcm2835_wdt\n"
                "        Falling back to systemd-only watchdog (sd_notify).",
                self.WDT_PATH,
            )
        except OSError as exc:
            self._log.warning(
                "[HWDog] Cannot open %s: %s — sd_notify mode only", self.WDT_PATH, exc
            )
        return False

    def _set_hw_timeout(self, seconds: int) -> int:
        """Ask the WDT driver for a specific timeout; returns the actual value set."""
        try:
            buf    = bytearray(struct.pack("i", seconds))
            result = fcntl.ioctl(self._fd.fileno(), self.WDIOC_SETTIMEOUT, buf)
            return struct.unpack("i", result)[0]
        except OSError:
            return seconds   # driver may not support SETTIMEOUT — use its default

    def _pet(self):
        """Reset the hardware WDT countdown and notify systemd."""
        with self._lock:
            if self._fd:
                try:
                    self._fd.write(b"\x01")   # any byte resets the timer
                    self._fd.flush()
                except OSError as exc:
                    self._log.error("[HWDog] Pet write failed: %s", exc)
        sd_notify("WATCHDOG=1")

    def _disarm(self):
        """Write the magic 'V' character to prevent a reboot on clean shutdown."""
        if self._fd:
            try:
                self._fd.write(b"V")   # magic close — disarms the WDT
                self._fd.flush()
                self._fd.close()
                self._log.info("[HWDog] Hardware watchdog disarmed (magic close 'V')")
            except OSError as exc:
                self._log.warning("[HWDog] Could not disarm cleanly: %s", exc)
            finally:
                self._fd = None

    def run(self):
        hw_available = self._open()
        mode = "hardware + systemd" if hw_available else "systemd-only (no /dev/watchdog)"
        self._log.info("[HWDog] Running in %s mode", mode)

        # Tell systemd our expected heartbeat interval
        sd_notify(f"WATCHDOG_USEC={self.PET_INTERVAL * 1_000_000}")

        while not self._stop_evt.wait(self.PET_INTERVAL):
            self._pet()

        self._log.debug("[HWDog] Thread exiting")


# ─────────────────────────────────────────────────────────────────────────────
# Main watchdog
# ─────────────────────────────────────────────────────────────────────────────

class Watchdog:
    def __init__(self, args):
        self._log_dir    = Path(args.log_dir)
        self._log        = setup_logger(self._log_dir)
        self._autoblock  = args.autoblock.lower() in ("true", "1", "yes")
        self._wan        = args.wan_iface
        self._lan        = args.lan_iface

        self._blocker    = IPBlocker(
            self._log_dir, args.block_expire, self._autoblock, self._log
        )
        self._notifier  = NotificationManager(self._log)
        self._shutdown  = EmergencyShutdown(self._wan, self._lan, self._log)
        self._hw_wdt    = HardwareWatchdog(self._log)
        self._threads: list[threading.Thread] = [
            self._hw_wdt,
            ARPMonitor(self._blocker, self._log),
            KernelLogMonitor(self._blocker, self._log),
            AuthLogMonitor(self._blocker, self._log),
            ServiceMonitor(self._log),
            ExpiryManager(self._blocker, self._log),
            StatusReporter(self._blocker, self._log),
        ]

        # AI Analyser (can be disabled via --no-ai)
        if not getattr(args, "no_ai", False):
            self._ai_analyser: Optional[AIAnalyser] = AIAnalyser(
                log_dir       = self._log_dir,
                notifier      = self._notifier,
                shutdown      = self._shutdown,
                logger        = self._log,
                poll_interval = args.ai_poll_interval,
                llm_endpoint  = args.llm_endpoint,
                llm_model     = args.llm_model,
            )
            self._threads.append(self._ai_analyser)
        else:
            self._ai_analyser = None

        self._stop_evt = threading.Event()

    def start(self):
        # Warn if a previous lockdown is still active
        if EmergencyShutdown.LOCKDOWN_MARKER.exists():
            self._log.critical(
                "[EMERGENCY] LOCKDOWN_ACTIVE marker found — gateway was locked down "
                "in a previous run.  Run: sudo python3 pi_watchdog.py --clear-lockdown"
            )

        self._log.info(
            "=== Pi Watchdog starting — WAN=%s  LAN=%s  autoblock=%s  AI=%s ===",
            self._wan, self._lan, self._autoblock,
            "enabled" if self._ai_analyser else "disabled",
        )
        for t in self._threads:
            t.start()

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

        # Tell systemd the service is fully initialised
        sd_notify("READY=1")

        self._stop_evt.wait()

        # Disarm hardware WDT BEFORE the process exits (clean shutdown)
        self._hw_wdt.stop()
        sd_notify("STOPPING=1")
        self._log.info("=== Pi Watchdog shutting down ===")

    def _handle_signal(self, signum, _frame):
        self._log.info("Received signal %d — stopping", signum)
        self._stop_evt.set()   # unblocks start() which will disarm HWdog + notify systemd


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Pi Security Watchdog — with AI threat analysis"
    )
    # ── Network ──
    p.add_argument("--wan-iface",    default="eth0",
                   help="WAN interface name (default: eth0)")
    p.add_argument("--lan-iface",    default="eth1",
                   help="LAN interface name (default: eth1)")
    # ── Logging / blocking ──
    p.add_argument("--log-dir",      default="/opt/chromecast_blocker/logs",
                   help="Directory for watchdog.log and blocklist.json")
    p.add_argument("--autoblock",    default="true",
                   help="true/false — auto-block via iptables (default: true)")
    p.add_argument("--block-expire", type=int, default=86400,
                   help="Seconds before an auto-block expires (default: 86400)")
    # ── AI analyser ──
    p.add_argument("--no-ai",        action="store_true",
                   help="Disable the AI threat analyser")
    p.add_argument("--ai-poll-interval", type=int, default=30,
                   help="Seconds between AI analysis cycles (default: 30)")
    p.add_argument("--llm-endpoint", default=None,
                   help="Ollama-compatible API base URL for LLM analysis "
                        "(e.g. http://localhost:11434). Omit to use rule-based only.")
    p.add_argument("--llm-model",    default="phi3:mini",
                   help="LLM model name at the llm-endpoint (default: phi3:mini)")
    # ── Maintenance ──
    p.add_argument("--clear-lockdown", action="store_true",
                   help="Clear an active emergency lockdown and restore gateway")
    return p.parse_args()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: pi_watchdog.py must run as root (needs iptables access)",
              file=sys.stderr)
        sys.exit(1)

    args = parse_args()

    # ── Maintenance mode: clear lockdown and exit ──────────────────────────
    if args.clear_lockdown:
        _log = setup_logger(Path(args.log_dir))
        EmergencyShutdown.clear(args.wan_iface, _log)
        sys.exit(0)

    Watchdog(args).start()
