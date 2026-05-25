# Chromecast Security Blocker — AI-Powered Gateway Defence

Stop Chromecast from sending **eavesdropping, telemetry and spy information** over the WAN —
guarded by a **four-layer defence system** where an AI threat-correlation engine works
side-by-side with a real-time security watchdog.

The recommended deployment runs on a **Raspberry Pi 4** inserted between your WAN router and
all local devices.  Every outbound packet is inspected and blocked before it reaches the internet.
Meanwhile the **AI Analyser** reads the compiled security log every 30 seconds, scores every
attack event, detects coordinated multi-vector intrusions, and — when the threat reaches a
critical level — can optionally consult a **local LLM (phi3:mini via ollama)** before deciding
whether to trigger an emergency internet lockdown.

A **browser-based Web UI** provides full control with a live terminal window, real-time status,
config editor, log viewer, and iptables inspector.  Everything can be operated from both the UI
and the command line simultaneously (parallel execution).

---

## Architecture — Four Layers of Defence

```
Internet ──► WAN Router ──► [ Pi 4 eth0 ]
                             [ Pi 4 eth1 ] ──► LAN Switch ──► Chromecast (blocked)
                                                           └──► Other devices (normal)

  Layer 1 (instant)   — iptables static DROP rules (ports, domains, WAN sources)
  Layer 2 (real-time) — pi_watchdog.py: ARP monitor, kernel-log scanner, SSH brute-force
                        detector — blocks offending IPs within milliseconds of threshold
  Layer 3 (30 s)      — AIAnalyser: scores every new log event, detects coordinated
                        multi-vector attacks, consults LLM if available, escalates to
                        emergency shutdown on FATAL threat level
  Layer 4 (hardware)  — BCM2711 hardware watchdog (/dev/watchdog): hard-reboots the Pi
                        if the software process ever hangs
```

See **[PI4_SETUP.md](PI4_SETUP.md)** for the complete Raspberry Pi 4 deployment guide.  
See **[AI_WATCHDOG_COOPERATION.md](AI_WATCHDOG_COOPERATION.md)** for the full AI + watchdog internals with diagrams.

---

Protect against unauthorized access, eavesdropping, and network attacks via Chromecast devices.
This tool blocks external access, prevents cloud connectivity for eavesdropping, protects against
DDoS amplification, defends against MITM attacks, and isolates your Chromecast to local network only.
All of this is continuously overseen by an **AI threat-scoring engine** that correlates events
across all attack types and can autonomously lock down the internet connection if the combined
threat level becomes critical.

## Security Threats

### 1. **Unauthorized Remote Access**
- External attackers can control your Chromecast remotely
- Device can be hijacked to display malicious content
- Access to your casting history and personal information

### 2. **Eavesdropping via Google Cloud**
- Chromecast continuously connects to Google servers
- Speech/audio data sent for processing
- Usage patterns tracked and analyzed
- Data shared with third parties

### 3. **DDoS Amplification**
- Compromised Chromecast used as attack vector
- mDNS/SSDP amplification attacks
- Your bandwidth consumed in large-scale attacks

### 4. **Man-in-the-Middle (MITM) Attacks**
- ARP spoofing to intercept traffic
- Credential theft from local network
- Malicious content injection

### 5. **Local Network Compromise**
- Chromecast exploited to access other devices
- Lateral movement to computers, phones, NAS
- Personal data exfiltration

## Features

### Firewall & Blocking
✅ Block external/WAN access to Chromecast  
✅ Block cloud connectivity and eavesdropping  
✅ Prevent DDoS amplification attacks  
✅ Defend against MITM attacks  
✅ Network isolation (local-only mode)  
✅ **DNS-level blocking** via dnsmasq (Chromecast can't bypass iptables with hardcoded DNS)  

### AI-Powered Watchdog (`pi_watchdog.py`)
✅ **AI Analyser** — reads the security log every 30 s and scores every attack event  
✅ **Threat level escalation** — NORMAL → SUSPICIOUS → CRITICAL → FATAL  
✅ **Coordination detection** — bonus score when the same IP uses 3+ attack types at once  
✅ **Optional local LLM** (phi3:mini via ollama) — can upgrade but never downgrade the AI score  
✅ **Emergency internet lockdown** — FORWARD=DROP + NAT flush + WAN interface down on FATAL  
✅ **ARP spoof / cable MITM detection** — MAC change alerts in real time  
✅ **SSH brute-force detection** — blocks after 4 failures in 120 s  
✅ **Port scan & flood detection** — NULL / XMAS / FIN / SYN scans, SYN / ICMP / UDP floods  
✅ **Hardware watchdog** — Pi hard-reboots automatically if the process ever hangs  
✅ **Auto-expiring IP blocks** — 24 h TTL, persisted across restarts  
✅ **Intrusion timeline viewer** (`trace_intruder.py`) — reconstruct any attack from the log  

### Monitoring & UI
✅ Real-time traffic monitoring  
✅ Suspicious activity logging to `watchdog.log` + `intrusions.log` + `ai_alerts.json`  
✅ Easy discovery of Chromecast devices  
✅ Per-device configuration  
✅ **Web UI with live terminal output** (xterm.js + WebSocket)  
✅ **AI alert panel** — browser polls `ai_alerts.json` every 5 s  
✅ **Parallel task execution** — run multiple operations simultaneously  
✅ **Raspberry Pi 4 gateway** — blocks at the network level, not just per-host  
✅ **Systemd services** — auto-start on boot, log rotation, restart on failure  

## Quick Start

### Option A — Raspberry Pi 4 (recommended, full isolation)

```bash
# Copy/clone the project to the Pi, then:
sudo bash pi4_gateway.sh

# Open Web UI
http://<pi-ip>:8080
```

See [PI4_SETUP.md](PI4_SETUP.md) for the complete step-by-step guide.

### Option B — Run directly on any Linux host

```bash
# Install dependencies
sudo bash install.sh

# Start the Web UI
python3 ui_server.py

# Or use the CLI directly
sudo python3 chromecast_blocker.py discover
sudo python3 chromecast_blocker.py full-protect --ip 10.42.0.1
```

## Installation

### Prerequisites
- Linux system (Ubuntu, Debian, Fedora, CentOS, Arch, etc.)
- Root/sudo access
- Python 3.6+

### Automated Installation
```bash
sudo bash install.sh
```

### Manual Installation
```bash
# Install system dependencies
sudo apt-get install python3 python3-pip iptables nmap avahi-utils tcpdump arptables

# Install Python dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x chromecast_blocker.py
```

## Usage

### 1. Discover Chromecast Devices
```bash
sudo python3 chromecast_blocker.py discover
```

Output:
```
Found Chromecast devices: 10.42.0.1, 10.42.0.2
```

### 2. Apply Full Protection (Recommended)
```bash
sudo python3 chromecast_blocker.py full-protect --ip 10.42.0.1
```

This applies all protections:
- Blocks external access
- Blocks eavesdropping/cloud connectivity
- Blocks DDoS amplification
- Protects against MITM attacks
- Isolates to local network only

### 3. Apply Specific Protections
```bash
# Block only external access
sudo python3 chromecast_blocker.py block --ip 10.42.0.1

# Monitor for suspicious activity
sudo python3 chromecast_blocker.py monitor --ip 10.42.0.1 --duration 600

# Check protection status
sudo python3 chromecast_blocker.py status --ip 10.42.0.1
```

### 4. Remove All Rules (Cleanup)
```bash
sudo python3 chromecast_blocker.py flush
```

## Configuration File

Edit `config.yaml` to configure multiple devices and settings:

```yaml
chromecast_devices:
  - ip: 10.42.0.1
    name: "Living Room"
    enabled: true

blocking:
  block_external: true
  block_eavesdropping: true
  block_ddos_amplification: true
  block_mitm: true
  isolate_local_only: true
```

## Web UI

Start the web server:

```bash
python3 ui_server.py [--host 0.0.0.0] [--port 8080]
# Then open: http://localhost:8080
```

| Tab | What it shows |
|-----|---------------|
| **Terminal** | Live xterm.js terminal — streams output from all running tasks in real time |
| **Status** | Per-device protection status, active iptables rule count, running task list |
| **Config** | Edit `config.yaml` directly in the browser with save/reload |
| **Logs** | Application logs with colour coding, optional auto-refresh every 3 s |
| **iptables** | Full `iptables-save` output, refreshable |

### Parallel Execution

Every action launched from the sidebar or terminal bar spawns its own **background thread +
subprocess**. Output streams to a new terminal tab automatically — tabs don't mix output.
You can also SSH into the Pi and run CLI commands at the same time; both sources are
independent.

Kill any running task from the sidebar (✕ button) or from the shell (`kill <pid>`).

## How It Works

### Layer 1 — Static Firewall Rules (instant)
- Uses iptables to DROP packets from WAN to Chromecast
- Only allows traffic from private IP ranges (192.168.x.x, 10.x.x.x, 172.16–31.x.x)
- Blocks DNS queries to Google domains; rate-limits cloud HTTP/HTTPS
- Rate-limits mDNS (5353), SSDP (1900), DNS (53), NTP (123)
- Drops ARP-spoofed, invalid, and malformed packets

### Layer 2 — Real-Time Rule-Based Watchdog (milliseconds)
- **KernelLogMonitor** streams `journalctl -k`, parses every iptables LOG line, and blocks
  an IP the moment it crosses the scan (2 events/60 s) or flood (5 events/60 s) threshold
- **AuthLogMonitor** streams the SSH journal and blocks after 4 failures in 120 s
- **ARPMonitor** polls `/proc/net/arp` every 5 s and alerts on any MAC address change
  (classic sign of a cable MITM / ARP poisoning attack)
- All blocked IPs are persisted to `blocklist.json` and expire automatically after 24 h

### Layer 3 — AI Threat Correlation Engine (every 30 seconds)
- Reads the last 200 lines of `watchdog.log` on each cycle
- Maps every event type to a numeric threat score (`THREAT_SCORE_MAP`)
- Awards a **coordination bonus (+3)** when the same source IP appears in 3 or more distinct
  attack categories simultaneously — this catches sophisticated attackers who combine scans,
  floods, and SSH probing in the same session
- Derives an overall threat level: **NORMAL (0–2) / SUSPICIOUS (3–5) / CRITICAL (6–9) / FATAL (≥10)**
- When `--llm-endpoint` is set and the score reaches SUSPICIOUS or above, the last 20 events
  are sent to a **local LLM (phi3:mini via ollama)** which can upgrade — but never downgrade —
  the threat classification
- **SUSPICIOUS / CRITICAL** → alert via `wall` broadcast + `ai_alerts.json` (Web UI)
- **FATAL** → same alerts + `EmergencyShutdown`: FORWARD=DROP, NAT flushed, WAN interface down

### Layer 4 — Hardware Watchdog (/dev/watchdog)
- Arms the BCM2711 built-in watchdog timer at startup (15 s hardware timeout)
- Sends a keep-alive every 10 s; also calls `sd_notify(WATCHDOG=1)` for systemd
- If the Python process **hangs** for any reason, the hardware timer fires and the Pi
  **hard-reboots automatically** — no human intervention needed
- On clean shutdown, writes the magic `'V'` character to disarm the WDT (no spurious reboot)

> Full diagrams and sequence flows: **[AI_WATCHDOG_COOPERATION.md](AI_WATCHDOG_COOPERATION.md)**

## Verification

Check if protections are applied:
```bash
sudo python3 chromecast_blocker.py status --ip 10.42.0.1
```

Output example:
```json
{
  "timestamp": "2026-05-21T14:30:00",
  "interface": "eth0",
  "active_rules": 24,
  "chromecast_ip": "10.42.0.1",
  "protections": {
    "external_access_blocked": true,
    "eavesdropping_blocked": true,
    "ddos_amplification_blocked": true,
    "mitm_protected": true,
    "isolated": true
  }
}
```

### View iptables Rules
```bash
sudo iptables -L -n
```

### Monitor Real-time Activity
```bash
sudo tcpdump -i eth0 host 10.42.0.1
```

## Systemd Integration

Install as a service that auto-starts:

```bash
sudo bash install.sh  # Choose to install as systemd service
sudo systemctl enable chromecast-blocker
sudo systemctl start chromecast-blocker
sudo systemctl status chromecast-blocker
```

Check logs:
```bash
sudo journalctl -u chromecast-blocker -f
```

## Firewall Rules Applied

The tool applies several layers of firewall rules:

1. **DROP external packets** destined for Chromecast
2. **ACCEPT only private network sources** (RFC1918)
3. **Rate-limit and DROP cloud connectivity** (Google domains)
4. **Block amplification ports** (mDNS, SSDP, DNS, NTP)
5. **DROP invalid/spoofed packets**
6. **Block Chromecast outbound WAN traffic**

## Troubleshooting

### Permission Denied
Must run as root:
```bash
sudo python3 chromecast_blocker.py discover
```

### iptables command not found
Install iptables:
```bash
sudo apt-get install iptables
```

### No Chromecast Found
Ensure Chromecast is on same network and powered on. Try manual IP:
```bash
sudo python3 chromecast_blocker.py status --ip 10.42.0.1
```

### Rules Not Persisting After Reboot
Install iptables-persistent:
```bash
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

Or use the systemd service for auto-application on boot.

## Logging

All activity logged to `chromecast_blocker.log`:
```bash
tail -f chromecast_blocker.log
```

## Uninstall

Remove rules:
```bash
sudo python3 chromecast_blocker.py flush
```

Remove service:
```bash
sudo systemctl stop chromecast-blocker
sudo systemctl disable chromecast-blocker
sudo rm /etc/systemd/system/chromecast-blocker.service
sudo systemctl daemon-reload
```

## Testing & Validation

### Before Protection
```bash
# Ping Chromecast (should respond)
ping 10.42.0.1

# Connect from another device on network (should work)
# Access web interface at http://10.42.0.1:8008
```

### After Protection
```bash
# Ping from same network (should work)
ping 10.42.0.1

# External requests to Chromecast (should fail)
# Cloud connectivity blocked
# Device isolated to local network
```

## Advanced Usage

### Monitor with Duration
```bash
sudo python3 chromecast_blocker.py monitor --ip 10.42.0.1 --duration 3600
```

### Specify Network Interface
```bash
sudo python3 chromecast_blocker.py full-protect --ip 10.42.0.1 --interface wlan0
```

## Security Notes

1. **Backup existing firewall rules** before running:
   ```bash
   sudo iptables-save > iptables-backup.txt
   ```

2. **Test rules carefully** in a non-production environment first

3. **Monitor logs** for any application issues:
   ```bash
   tail -f chromecast_blocker.log
   ```

4. **Keep system updated** for latest security patches

5. **Consider removing Chromecast** entirely if not needed for your use case

## Legal Disclaimer

This tool is designed for defensive security purposes on your own network. Unauthorized use on networks you do not own or have permission to protect is illegal. Use only on systems you have explicit authorization to modify.

## Support

For issues, suggestions, or contributions, please check the logs and ensure:
- Running as root
- All dependencies installed
- Network interface correctly specified
- Chromecast IP address is correct

## License

This tool is provided as-is for network security protection purposes.
