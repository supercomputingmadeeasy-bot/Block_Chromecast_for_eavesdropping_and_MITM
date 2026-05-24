#!/usr/bin/env python3
"""
trace_intruder.py — Intrusion timeline viewer for the Pi Security Watchdog

Reads the structured log lines written by pi_watchdog.py and reconstructs
a human-readable timeline showing WHERE and HOW each intrusion attempt
took place: attack type, targeted ports, protocol, interface, attacker's
reverse-DNS, SSH username tried, block status, etc.

Usage:
  sudo python3 trace_intruder.py                      # list every intruder
  sudo python3 trace_intruder.py --ip 1.2.3.4         # full timeline for IP
  sudo python3 trace_intruder.py --since 24h           # last 24 h only
  sudo python3 trace_intruder.py --since 7d --ip 5.6.7.8
  sudo python3 trace_intruder.py --log /path/to/watchdog.log

Exit codes:  0 = OK,  1 = bad args,  2 = no log found
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_WATCHDOG_LOG  = Path("/opt/chromecast_blocker/logs/watchdog.log")
DEFAULT_INTRUSION_LOG = Path("/opt/chromecast_blocker/logs/intrusions.log")

# ─────────────────────────────────────────────────────────────────────────────
# Regexes matching the structured lines emitted by pi_watchdog.py
# ─────────────────────────────────────────────────────────────────────────────

# 2026-05-24 12:34:56 [WARNING] [ATTACK]   eid=a1b2c3d4 src=1.2.3.4 ...
# 2026-05-24 12:34:56 [WARNING] [SSH-FAIL] eid=...
# 2026-05-24 12:34:56 [WARNING] [BLOCKED]  eid=...
# 2026-05-24 12:34:56 [CRITICAL] [ARP-SPOOF] eid=...
LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+\[(?P<level>\w+)\]"
    r"\s+\[(?P<cat>[^\]]+)\]"
    r"\s+(?P<body>.+)$"
)
KV_RE = re.compile(r'(\w+)=("[^"]*"|\'[^\']*\'|[^\s]+)')

ATTACK_CATS = {"ATTACK", "SSH-FAIL", "BLOCKED", "ALERT", "ARP-SPOOF"}

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colours (disabled automatically if not a tty)
# ─────────────────────────────────────────────────────────────────────────────
_USE_COLOUR = sys.stdout.isatty()

def _c(code: str) -> str:
    return code if _USE_COLOUR else ""

RESET  = _c("\033[0m")
BOLD   = _c("\033[1m")
RED    = _c("\033[31m")
YELLOW = _c("\033[33m")
CYAN   = _c("\033[36m")
GREEN  = _c("\033[32m")
GREY   = _c("\033[90m")
DIM    = _c("\033[2m")

LEVEL_COLOUR = {
    "CRITICAL": RED + BOLD,
    "WARNING":  YELLOW,
    "INFO":     CYAN,
}
CAT_ICON = {
    "ATTACK":   "SCAN/FLOOD",
    "SSH-FAIL": "SSH-FAIL  ",
    "BLOCKED":  "BLOCKED   ",
    "ALERT":    "ALERT     ",
    "ARP-SPOOF":"ARP-SPOOF ",
}

# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_kv(body: str) -> dict:
    d = {}
    for m in KV_RE.finditer(body):
        val = m.group(2).strip("'\"")
        d[m.group(1)] = val
    return d


def _src_ip(event: dict) -> str:
    """Return the attacker's IP regardless of which field it's stored in."""
    return event.get("src") or event.get("ip") or ""


def parse_log(path: Path, since_dt: Optional[datetime] = None) -> list:
    events = []
    if not path.exists():
        return events
    try:
        with open(path) as fh:
            for raw in fh:
                m = LOG_LINE_RE.match(raw.rstrip())
                if not m:
                    continue
                cat = m.group("cat")
                if cat not in ATTACK_CATS:
                    continue
                ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S")
                if since_dt and ts < since_dt:
                    continue
                ev = _parse_kv(m.group("body"))
                ev.update({
                    "_ts":    ts,
                    "_level": m.group("level"),
                    "_cat":   cat,
                    "_raw":   m.group("body"),
                })
                events.append(ev)
    except OSError as exc:
        print(f"[!] Cannot read {path}: {exc}", file=sys.stderr)
    return events


def load_events(log_path: Path, since_dt: Optional[datetime]) -> list:
    """Load and deduplicate events (by eid) from watchdog + intrusions logs."""
    events = parse_log(log_path, since_dt)
    # Also pull from intrusions.log if it exists alongside watchdog.log
    sibling = log_path.parent / "intrusions.log"
    if sibling != log_path:
        events += parse_log(sibling, since_dt)
    seen: set = set()
    unique = []
    for ev in events:
        key = ev.get("eid") or id(ev)
        if key not in seen:
            seen.add(key)
            unique.append(ev)
    return sorted(unique, key=lambda e: e["_ts"])

# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_duration(delta: timedelta) -> str:
    s = int(delta.total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _detail_line(ev: dict) -> str:
    cat = ev["_cat"]
    if cat == "ATTACK":
        return (
            f"type={ev.get('type','?'):14s}  proto={ev.get('proto','?'):<4s}  "
            f"spt={ev.get('spt','?'):>6s} \u2192 dpt={ev.get('dpt','?'):<6s}  "
            f"in={ev.get('in','?'):<6s}  ttl={ev.get('ttl','?'):>3s}  "
            f"len={ev.get('len','?'):>5s}  mac={ev.get('mac','?')}"
        )
    if cat == "SSH-FAIL":
        return (
            f"user={ev.get('user','?'):<16s}  method={ev.get('method','?'):<12s}  "
            f"src_port={ev.get('port','?'):<6s}  attempt={ev.get('attempt','?')}"
        )
    if cat in ("BLOCKED", "ALERT"):
        return f"reason={ev.get('reason','?')}   expires={ev.get('expires','?')}"
    if cat == "ARP-SPOOF":
        return (
            f"iface={ev.get('iface','?'):<8s}  "
            f"old_mac={ev.get('old_mac','?')} \u2192 new_mac={ev.get('new_mac','?')}"
        )
    return ev.get("_raw", "")[:80]

# ─────────────────────────────────────────────────────────────────────────────
# Main output modes
# ─────────────────────────────────────────────────────────────────────────────

def show_timeline(ip: str, events: list):
    """Print full chronological attack timeline for one IP."""
    ip_events = [e for e in events if _src_ip(e) == ip]
    if not ip_events:
        print(f"\n  No events recorded for {ip}\n")
        return

    rdns      = next((e.get("rdns", ip) for e in ip_events if e.get("rdns") and e.get("rdns") != ip), ip)
    first_ts  = ip_events[0]["_ts"]
    last_ts   = ip_events[-1]["_ts"]
    duration  = _fmt_duration(last_ts - first_ts)

    blocked_evs = [e for e in ip_events if e["_cat"] in ("BLOCKED", "ALERT")]
    attack_evs  = [e for e in ip_events if e["_cat"] == "ATTACK"]
    ssh_evs     = [e for e in ip_events if e["_cat"] == "SSH-FAIL"]
    arp_evs     = [e for e in ip_events if e["_cat"] == "ARP-SPOOF"]

    # Summarise attack vectors
    attack_types = Counter(e.get("type", e["_cat"]) for e in attack_evs)
    protos       = Counter(e.get("proto", "?") for e in attack_evs if e.get("proto"))
    dpts         = Counter(e.get("dpt",   "?") for e in attack_evs if e.get("dpt") not in (None, "?"))
    in_ifaces    = Counter(e.get("in",    "?") for e in attack_evs if e.get("in"))
    ssh_users    = Counter(e.get("user",  "?") for e in ssh_evs)

    W = 72
    print(f"\n{'═' * W}")
    print(f"{BOLD}  Intrusion Report: {CYAN}{ip}{RESET}")
    print(f"{'─' * W}")
    print(f"  Reverse DNS     : {CYAN}{rdns}{RESET}")
    print(f"  First seen      : {_fmt_ts(first_ts)}")
    print(f"  Last seen       : {_fmt_ts(last_ts)}")
    print(f"  Attack duration : {duration}")
    print(f"  Total events    : {len(ip_events)}")

    if attack_types:
        types_str = "  ".join(f"{t}×{c}" for t, c in attack_types.most_common())
        print(f"  Attack types    : {YELLOW}{types_str}{RESET}")
    if protos:
        print(f"  Protocols       : {', '.join(f'{p}×{c}' for p, c in protos.most_common())}")
    if dpts:
        print(f"  Ports targeted  : {', '.join(f'{p}×{c}' for p, c in dpts.most_common(12))}")
    if in_ifaces:
        print(f"  Arrived on      : {', '.join(f'{i}×{c}' for i, c in in_ifaces.most_common())}")
    if ssh_users:
        users_str = "  ".join(f"{u}×{c}" for u, c in ssh_users.most_common(8))
        print(f"  SSH users tried : {YELLOW}{users_str}{RESET}")
    if arp_evs:
        print(f"  {RED}ARP SPOOF ALERTS{RESET}: {len(arp_evs)}")

    if blocked_evs:
        be = blocked_evs[-1]
        print(f"\n  {RED+BOLD}BLOCKED{RESET}  at {_fmt_ts(be['_ts'])}  "
              f"expires={be.get('expires','?')}  "
              f"eid={be.get('eid','?')}")
    else:
        print(f"\n  {YELLOW}Status: not yet blocked — still active{RESET}")

    print(f"\n{'─' * W}")
    print(f"  {'TIMESTAMP':<20}  {'CATEGORY':<12}  DETAIL")
    print(f"{'─' * W}")

    for ev in ip_events:
        col  = LEVEL_COLOUR.get(ev["_level"], "")
        cat  = CAT_ICON.get(ev["_cat"], ev["_cat"])
        ts_s = _fmt_ts(ev["_ts"])
        det  = _detail_line(ev)
        eid  = GREY + f"[{ev.get('eid','?')}]" + RESET
        print(f"  {ts_s}  {col}{cat}{RESET}  {det}  {eid}")

    print(f"{'═' * W}\n")


def list_intruders(events: list):
    """Print a summary table of every attacking source IP."""
    by_ip: dict = defaultdict(list)
    for ev in events:
        ip = _src_ip(ev)
        if ip:
            by_ip[ip].append(ev)

    if not by_ip:
        print("\n  No intrusion events found in logs.\n")
        return

    # Sort by most recent event first
    sorted_ips = sorted(by_ip.items(), key=lambda kv: kv[1][-1]["_ts"], reverse=True)

    W = 90
    print(f"\n{'═' * W}")
    print(
        f"{BOLD}  {'SRC IP':<18}  {'REVERSE DNS':<28}  "
        f"{'EVT':>4}  {'FIRST SEEN':<20}  {'LAST SEEN':<20}  STATUS{RESET}"
    )
    print(f"{'─' * W}")

    for ip, evs in sorted_ips:
        rdns    = next((e.get("rdns", ip) for e in evs if e.get("rdns") and e.get("rdns") != ip), ip)
        rdns_s  = (rdns[:26] + "..") if len(rdns) > 28 else rdns
        blocked = any(e["_cat"] in ("BLOCKED", "ALERT") for e in evs)
        arp     = any(e["_cat"] == "ARP-SPOOF" for e in evs)
        ssh     = any(e["_cat"] == "SSH-FAIL" for e in evs)

        flags = []
        if blocked: flags.append(f"{RED}BLOCKED{RESET}")
        if arp:     flags.append(f"{RED}ARP!{RESET}")
        if ssh:     flags.append(f"{YELLOW}SSH{RESET}")
        if not flags: flags.append(f"{YELLOW}active{RESET}")
        status = " ".join(flags)

        first_ts = _fmt_ts(evs[0]["_ts"])
        last_ts  = _fmt_ts(evs[-1]["_ts"])
        print(
            f"  {ip:<18}  {rdns_s:<28}  "
            f"{len(evs):>4}  {first_ts:<20}  {last_ts:<20}  {status}"
        )

    print(f"{'─' * W}")
    print(
        f"  {BOLD}{len(by_ip)} unique attacker IPs  |  "
        f"{sum(len(v) for v in by_ip.values())} total events{RESET}"
    )
    print(f"  Run with  --ip <addr>  to see the full attack timeline for any IP.\n")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    ap = argparse.ArgumentParser(
        description="Trace intrusions from pi_watchdog structured logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 trace_intruder.py                  # list all intruders
  sudo python3 trace_intruder.py --ip 1.2.3.4     # timeline for one IP
  sudo python3 trace_intruder.py --since 24h       # last 24 hours
  sudo python3 trace_intruder.py --since 7d --ip 5.6.7.8
        """,
    )
    ap.add_argument("--ip",    metavar="ADDR",
                    help="Show full attack timeline for this source IP")
    ap.add_argument("--since", metavar="PERIOD",
                    help="Limit to events within this period: 30m | 24h | 7d")
    ap.add_argument("--log",   metavar="FILE",
                    default=str(DEFAULT_WATCHDOG_LOG),
                    help=f"Log file (default: {DEFAULT_WATCHDOG_LOG})")
    return ap.parse_args()


def _parse_since(period: str) -> datetime:
    unit_map = {"m": 60, "h": 3600, "d": 86400}
    try:
        unit  = period[-1].lower()
        value = int(period[:-1])
        return datetime.now() - timedelta(seconds=value * unit_map[unit])
    except (KeyError, ValueError, IndexError):
        print(f"[!] Invalid --since format: {period!r}  (use e.g. 30m, 24h, 7d)",
              file=sys.stderr)
        sys.exit(1)


def main():
    args     = parse_args()
    log_path = Path(args.log)
    since_dt = _parse_since(args.since) if args.since else None

    if not log_path.exists():
        print(f"[!] Log file not found: {log_path}\n"
              f"    Is pi-watchdog.service running?  "
              f"systemctl status pi-watchdog",
              file=sys.stderr)
        sys.exit(2)

    events = load_events(log_path, since_dt)

    if since_dt:
        print(f"\n  Showing events since {_fmt_ts(since_dt)}")

    if args.ip:
        show_timeline(args.ip, events)
    else:
        list_intruders(events)


if __name__ == "__main__":
    main()
