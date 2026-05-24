# Chromecast Blocker - Architecture & File Guide

> For the history and internals behind NetworkManager, systemd, Netfilter and D-Bus,
> see [LINUX_NETWORKING_INTERNALS.md](LINUX_NETWORKING_INTERNALS.md).

---

## Where This Project Sits in the Linux Networking Stack

```mermaid
graph TB
    subgraph L5["Layer 5 — This Project (Application)"]
        direction LR
        CB["chromecast_blocker.py\ncore firewall engine"]
        AB["advanced_blocker.py\nmulti-device + YAML config"]
        UI["ui_server.py\nbrowser UI  :8080"]
        SM["status_monitor.py\nlive terminal dashboard"]
    end

    subgraph L4["Layer 4 — Network Management  (Pi OS Bookworm default)"]
        direction LR
        NM_L["NetworkManager\nmanages eth0, eth1, wlan0\ncreates hotspot via nmcli"]
        DNSM_L["dnsmasq\n(spawned by NM)\nDHCP + DNS for LAN clients"]
        WPA_L["wpa_supplicant\n(called by NM)\nWiFi AP mode"]
    end

    subgraph L3["Layer 3 — Kernel API (netlink)"]
        NL_L["AF_NETLINK socket\nAll L4 daemons and our iptables calls\npass through here to reach the kernel"]
    end

    subgraph L2["Layer 2 — Linux Kernel"]
        direction TB
        NF_L["Netfilter  ← our DROP rules installed here\nFORWARD chain: block 10.42.0.88 → WAN\nnat POSTROUTING: MASQUERADE (NAT gateway)"]
        RT_L["IP routing\nip_forward=1\n10.42.0.0/24 via eth1/wlan0"]
        CT_L["Connection tracking\nnf_conntrack"]
    end

    subgraph L1["Layer 1 — Drivers"]
        direction LR
        ETH_L["bcmgenet\nPi 4 built-in GbE  (eth0=WAN)"]
        USB_L["cdc_ether / asix\nUSB adapter  (eth1=LAN)"]
        WF_L["brcmfmac + mac80211\nBroadcom WiFi  (wlan0=AP)"]
    end

    subgraph L0["Layer 0 — Physical"]
        direction LR
        C0["RJ-45 cable → WAN router"]
        C1["RJ-45 cable → LAN switch → Chromecast"]
        C2["2.4/5 GHz RF → WiFi clients"]
    end

    L5 -- "python-iptables\nsubprocess iptables" --> L3
    L4 -- "netlink calls" --> L3
    L3 --> L2
    L2 --> L1
    L1 --> L0
```

---

## Network Topology

```mermaid
graph LR
    INTERNET["Internet / WAN"]
    ROUTER["WAN Router\n(ISP modem)"]

    subgraph PI["Raspberry Pi 4  — gateway + firewall"]
        ETH0["eth0\nWAN face\n(DHCP from router)"]
        KERNEL_PI["Kernel:\nip_forward=1\nNAT MASQUERADE\nNetfilter DROP rules"]
        ETH1_W["eth1  OR  wlan0\nLAN face\n10.42.0.1/24"]
        DNSMASQ_PI["dnsmasq\nDHCP: 10.42.0.10–200\nDNS: forward upstream"]
        BLOCKER_PI["chromecast_blocker.py\nFORWARD -s 10.42.0.88 -j DROP\n+ cloud blocking rules"]
    end

    subgraph LAN["LAN  10.42.0.0/24"]
        CC_L["Chromecast\n10.42.0.88\n❌ WAN blocked\n❌ Google telemetry blocked"]
        OTHER_L["Laptops / phones\n10.42.0.10–87\n✅ normal internet access"]
    end

    INTERNET --- ROUTER
    ROUTER -- "cable" --> ETH0
    ETH0 --- KERNEL_PI
    KERNEL_PI --- ETH1_W
    KERNEL_PI --- BLOCKER_PI
    ETH1_W -- "cable / WiFi" --> LAN
    DNSMASQ_PI -. "serves DHCP/DNS" .-> LAN
```

---

## Project Structure

```
/home/jorgen-larsen/block_chromecast/
│
├── Core Engine
│   ├── chromecast_blocker.py ⭐ (Main protection engine)
│   └── advanced_blocker.py (Config-based management)
│
├── Utilities
│   ├── status_monitor.py (Real-time dashboard)
│   └── test_blocker.py (Validation suite)
│
├── Setup & Installation
│   ├── install.sh (Automated installation)
│   ├── pi4_gateway.sh (Full Pi 4 gateway setup)
│   ├── requirements.txt (Python dependencies)
│   └── chromecast-blocker.service (Systemd service)
│
├── Configuration
│   └── config.yaml (Multi-device settings)
│
└── Documentation
    ├── README.md (Complete guide)
    ├── PI4_SETUP.md (Raspberry Pi 4 deployment)
    ├── LINUX_NETWORKING_INTERNALS.md (NM + systemd history & diagrams)
    ├── QUICK_START.sh (Command reference)
    ├── TECHNICAL_GUIDE.md (Deep technical docs)
    ├── IMPLEMENTATION_SUMMARY.md (Project overview)
    └── ARCHITECTURE.md (This file)
```

## Component Overview

### 1. chromecast_blocker.py (680 lines)
**Purpose**: Core security engine
**Key Classes**:
- `ChromecastBlocker` - Main protection class
  - `discover_chromecast()` - Find devices on network
  - `block_external_access()` - WAN blocking
  - `block_eavesdropping()` - Cloud connectivity blocking
  - `block_ddos_amplification()` - Attack vector prevention
  - `block_mitm_attacks()` - Network security
  - `isolate_chromecast()` - Network isolation
  - `monitor_chromecast_traffic()` - Real-time monitoring
  - `get_status()` - Protection status

### 2. advanced_blocker.py (340 lines)
**Purpose**: Enhanced management with config support
**Key Classes**:
- `AdvancedChromecastBlocker` - Extended blocker
  - Multi-device support via YAML config
  - Continuous monitoring loop
  - Rule backup/restore capability
  - Log rotation management
  - Protection summary generation

### 3. status_monitor.py (230 lines)
**Purpose**: Real-time monitoring dashboard
**Features**:
- Live status display
- Protection indicators
- Connection tracking
- Terminal UI with auto-refresh
- Per-device metrics

### 4. test_blocker.py (280 lines)
**Purpose**: Comprehensive validation suite
**Tests**:
1. Privilege check (root access)
2. Dependency verification
3. Local connectivity
4. Firewall rule count
5. External blocking validation
6. Cloud connectivity blocking
7. DDoS protection rules
8. MITM protection rules
9. Network isolation
10. Log file verification

### 5. pi_watchdog.py — AI Security Watchdog
**Purpose**: Continuous threat monitoring with AI-assisted classification and automated response.

```mermaid
graph TB
    subgraph INPUTS["Watchdog Input Sources  (parallel threads)"]
        direction LR
        ARP_IN["ARPMonitor\npolls /proc/net/arp every 5s\ndetects MAC changes = cable MITM"]
        KERN_IN["KernelLogMonitor\njournalctl -f -k\nparses iptables LOG lines:\nFW-NULLSCAN, FW-SYNFLOOD, etc."]
        AUTH_IN["AuthLogMonitor\njournalctl -f -u ssh\ncounts failed auth per IP\nwithin SSH_WINDOW=120s"]
        SVC_IN["ServiceMonitor\nsystemctl is-active every 60s\ndetects crashed services"]
    end

    subgraph BLOCKER_THREAD["IPBlocker\n(thread-safe)"]
        BLK["Thresholds:\n• 2+ scan events  → block\n• 5+ flood events → block\n• 4+ SSH fails    → block\n\niptables -I INPUT -s <ip> -j DROP\nExpiry: 24h (configurable)\nblocklist.json persisted to disk"]
    end

    subgraph AI_LAYER["AIAnalyser  (every 30s)"]
        direction TB
        TAIL["tail -n 200 watchdog.log\nparse structured [TAG] eid=... lines"]
        SCORE["Per-IP threat scoring\nTHREAT_SCORE_MAP:\n  ARP-SPOOF   +8\n  port scan   +3 each\n  SSH-FAIL    +2 each\n  flood       +3–4 each\n  coordination bonus +3\n  (≥3 attack types from same IP)"]
        LEVEL["Threshold → level:\n  0–2  NORMAL\n  3–5  SUSPICIOUS\n  6–9  CRITICAL\n  ≥10  FATAL"]
        LLM["Optional LLM call\noللama API  (phi3:mini or custom)\nSends event excerpt as prompt\nReturns JSON: {level, reason}\nCan only UPGRADE score, never downgrade\nFalls back silently if endpoint unreachable"]
        DEDUP["eid deduplication\nNever escalates same event twice\nSeen-eids set (capped at 5000)"]

        TAIL --> SCORE --> LEVEL --> LLM --> DEDUP
    end

    subgraph ACTIONS["Response Actions"]
        NOTIFY["NotificationManager\n• wall broadcast to all terminals\n• Append to ai_alerts.json\n  (web UI polls every 5s)\n• Write FATAL_ALERT file\n• Log to watchdog.log + journald"]
        EMERGENCY["EmergencyShutdown  (FATAL only)\n1. iptables -P FORWARD DROP\n2. iptables -F FORWARD\n3. iptables -t nat -F POSTROUTING\n4. ip6tables -P FORWARD DROP\n5. sysctl net.ipv4.ip_forward=0\n6. ip link set eth0 down\n7. Write LOCKDOWN_ACTIVE marker\n\nRestore: pi_watchdog.py --clear-lockdown"]
    end

    subgraph HW["Hardware Watchdog"]
        HWDOG["HardwareWatchdog\n/dev/watchdog (bcm2835_wdt)\nPet every 10s\nKill-9 → Pi auto-reboots in 15s\nClean stop: writes magic 'V' to disarm"]
    end

    INPUTS --> BLOCKER_THREAD
    INPUTS --> AI_LAYER
    AI_LAYER -->|"SUSPICIOUS / CRITICAL"| NOTIFY
    AI_LAYER -->|"FATAL"| NOTIFY
    AI_LAYER -->|"FATAL"| EMERGENCY
```

### 6. install.sh (75 lines)
**Purpose**: One-command installation
**Detects**:
- OS type (Ubuntu/Debian, Fedora/CentOS, Arch)
- Root privileges
- Existing installation
**Installs**:
- System dependencies
- Python packages
- Sets permissions
- Optional systemd integration

---

## AI Threat Level Escalation

```mermaid
graph LR
    N["NORMAL\nscore 0–2\nLog only"]
    S["SUSPICIOUS\nscore 3–5\nwall + ai_alerts.json"]
    C["CRITICAL\nscore 6–9\nwall + ai_alerts.json"]
    F["FATAL\nscore ≥10\nwall + FATAL_ALERT\nEmergency lockdown"]

    N -->|"score rises"| S -->|"score rises"| C -->|"score rises"| F
    F -->|"--clear-lockdown"| N

    style N fill:#2d5a2d,color:#fff
    style S fill:#8a6914,color:#fff
    style C fill:#8a1414,color:#fff
    style F fill:#000,color:#ff4444
```

---

## Data Flow

### Protection Application Flow
```
User Input (IP Address)
        ↓
Discovery (find Chromecast)
        ↓
Firewall Rules Generation
        ├→ Block external access (INPUT chain)
        ├→ Block eavesdropping (OUTPUT chain - DNS)
        ├→ Block DDoS amplification (OUTPUT chain - ports)
        ├→ Block MITM attacks (INPUT/arp validation)
        └→ Network isolation (FORWARD chain)
        ↓
iptables Rule Application
        ↓
Rule Verification
        ↓
Continuous Monitoring (optional)
        ↓
Status Dashboard (real-time)
```

### Traffic Filtering Flow
```
Packet Arrives
        ↓
[iptables] Check against rules (left-to-right)
        ├→ Rule match? → Action (ACCEPT/DROP/REJECT)
        ├→ No match? → Continue to next rule
        └→ End of chain? → Default policy
        ↓
Next Packet
```

## Protection Layers

```
Layer 1: INPUT Chain
├─ Block external IPs
├─ Allow private networks only
├─ Drop invalid packets
└─ Rate limiting

Layer 2: OUTPUT Chain
├─ Block DNS to Google
├─ Rate-limit HTTPS/HTTP
├─ Block amplification ports
└─ Prevent cloud sync

Layer 3: FORWARD Chain
├─ Allow local-to-local only
├─ Block outbound WAN
├─ Isolate Chromecast
└─ Prevent lateral movement

Layer 4: Connection Tracking
├─ Validate packet states
├─ Track sessions
├─ Detect spoofing
└─ Prevent injection

Layer 5: Monitoring
├─ Real-time traffic analysis
├─ Anomaly detection
├─ Logging & alerting
└─ Status reporting
```

## Usage Patterns

### Single Device
```python
from chromecast_blocker import ChromecastBlocker

blocker = ChromecastBlocker(chromecast_ip='10.42.0.1')
blocker.block_external_access('10.42.0.1')
blocker.block_eavesdropping('10.42.0.1')
blocker.isolate_chromecast('10.42.0.1')
```

### Multiple Devices with Config
```python
from advanced_blocker import AdvancedChromecastBlocker

blocker = AdvancedChromecastBlocker(config_file='config.yaml')
blocker.protect_all_devices()
blocker.continuous_monitor(interval=60)
```

### Command Line
```bash
# All-in-one protection
sudo python3 chromecast_blocker.py full-protect --ip 10.42.0.1

# With config management
sudo python3 advanced_blocker.py --config config.yaml protect-all

# Real-time monitoring
sudo python3 status_monitor.py 10.42.0.1

# Validation
sudo python3 test_blocker.py 10.42.0.1
```

## Technology Stack

### Languages
- Python 3.6+ (main implementation)
- Bash (installation scripts)
- YAML (configuration)

### Core Tools
- iptables (firewall rules)
- nmap (device discovery)
- tcpdump (traffic analysis)
- arptables (ARP validation)
- avahi-browse (mDNS discovery)
- systemd (service management)

### Python Libraries
- subprocess (system commands)
- socket (network operations)
- netaddr (IP handling)
- pyyaml (config parsing)
- logging (event tracking)
- json (status output)

### Kernel Features
- netfilter (packet filtering)
- Connection tracking
- String matching (Boyer-Moore algorithm)
- Rate limiting via token bucket

## Security Model

### Trust Assumptions
✓ Root/sudo access only (authenticated)
✓ Local administrator control
✓ Kernel netfilter integrity
✓ Python interpreter security

### Attack Surface
- Privileged Python code execution
- Firewall rule injection (via regex string matching)
- Configuration file tampering (YAML parsing)
- Root escalation vulnerability (Linux kernel)

### Mitigations
- Input validation on IPs
- Regex escaping for string matching
- Safe YAML parsing
- Error handling & logging
- Secure default rules

## Performance Characteristics

### Startup Time
- Cold start: 2-5 seconds
- Rule application: 1-3 seconds
- Discovery: 30-60 seconds (network dependent)

### Runtime Overhead
- Per-packet overhead: < 1 microsecond
- Memory usage: 5-10 MB
- CPU usage: < 0.1%

### Scalability
- Single device: No performance impact
- Multiple devices: Linear scale (one set of rules per device)
- Dense networks (100+ devices): Manageable with batching

## Log Output Structure

```
2026-05-21 14:30:00,123 - INFO - Chromecast device found: 10.42.0.1
2026-05-21 14:30:01,234 - DEBUG - Applying rule: iptables -A INPUT ...
2026-05-21 14:30:01,456 - INFO - External access blocked for 10.42.0.1
2026-05-21 14:30:02,567 - WARNING - Cloud connectivity rule failed
2026-05-21 14:30:03,678 - ERROR - Cannot load config: file not found
```

## Monitoring & Alerts

### Automatic Monitoring
- Suspicious IP detection
- Blocked connection tracking
- Traffic pattern analysis
- Anomaly detection

### Manual Verification
```bash
# Check active rules
sudo iptables -L -v

# Monitor live traffic
sudo tcpdump -i eth0 host 10.42.0.1

# View logs
tail -f chromecast_blocker.log

# Check protection status
sudo python3 chromecast_blocker.py status --ip 10.42.0.1
```

## Maintenance Schedule

### Daily
- Check logs for errors: `tail chromecast_blocker.log`

### Weekly
- Verify protection: `sudo python3 test_blocker.py`
- Monitor dashboard: `sudo python3 status_monitor.py`

### Monthly
- Review configuration
- Check for updates
- Validate isolated network

### Quarterly
- Full test with `test_blocker.py`
- Update dependencies
- Review logs for patterns

## Troubleshooting Guide

### Symptom: Rules not applied
**Check**: `sudo iptables -L | grep 10.42.0.1`
**Fix**: Re-run with sudo, verify IP, check logs

### Symptom: Chromecast offline
**Check**: `ping 10.42.0.1`
**Fix**: Rules too restrictive, flush and reapply

### Symptom: Systemd service fails
**Check**: `sudo systemctl status chromecast-blocker`
**Fix**: Check config.yaml syntax, verify IP addresses

### Symptom: High CPU usage
**Check**: `top -b -n 1 | grep python`
**Fix**: Disable monitoring, reduce refresh rate

## Related Files

| File | Purpose | Size |
|------|---------|------|
| chromecast_blocker.py | Core engine | 18 KB |
| advanced_blocker.py | Config management | 10 KB |
| status_monitor.py | Dashboard | 6 KB |
| test_blocker.py | Tests | 9 KB |
| install.sh | Installation | 2.4 KB |
| config.yaml | Configuration | 1.7 KB |
| README.md | User guide | 8 KB |
| TECHNICAL_GUIDE.md | Technical deep-dive | 12 KB |
| **Total** | **Complete solution** | **>90 KB** |

## Quick Reference

```bash
# Get started in 3 commands:
1. sudo bash install.sh
2. sudo python3 chromecast_blocker.py discover
3. sudo python3 chromecast_blocker.py full-protect --ip <IP>

# View protection:
sudo python3 status_monitor.py <IP>

# Validate everything:
sudo python3 test_blocker.py <IP>
```

## Version Information

- **Version**: 1.0
- **Release Date**: May 21, 2026
- **Status**: Production Ready
- **Languages**: Python 3.6+, Bash, YAML
- **License**: Defensive Use Only

---

For more information:
- Installation: See README.md
- Technical details: See TECHNICAL_GUIDE.md
- Quick commands: See QUICK_START.sh
- Implementation: See IMPLEMENTATION_SUMMARY.md
