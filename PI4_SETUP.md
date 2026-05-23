# Raspberry Pi 4 — WAN Gateway & Chromecast Privacy Firewall

## Goal

Insert a Raspberry Pi 4 **between your WAN router and all local devices**.
Every packet the Chromecast tries to send to the internet passes through the Pi,
where it is inspected and blocked.  
No telemetry, no eavesdropping data, no spy information ever reaches Google's servers.

---

## Network Topology

```
 ┌─────────────┐  Ethernet cable   ┌──────────────────────────────┐
 │  WAN Router │ ─────────────────► │  Raspberry Pi 4              │
 │ (ISP modem) │  (gets DHCP IP     │                              │
 │             │   from router)     │  eth0 ← WAN  (DHCP from router)
 └─────────────┘                    │  eth1 → LAN  (static 10.42.0.1)
                                    │                              │
                                    │  Runs:                       │
                                    │  • iptables NAT + firewall   │
                                    │  • chromecast_blocker.py     │
                                    │  • Web UI on port 8080       │
                                    └──────────────┬───────────────┘
                                                   │ Ethernet cable
                                                   ▼
                                         ┌─────────────────┐
                                         │  LAN Switch      │
                                         └────┬───────┬─────┘
                                              │       │
                                         ┌────▼──┐ ┌──▼──────────┐
                                         │Chromecast│ │ Other devices│
                                         │(blocked) │ │ (normal)    │
                                         └──────────┘ └─────────────┘
```

The Pi acts as a **NAT gateway**: it forwards legitimate local traffic to the internet
but silently drops everything Chromecast tries to leak.

---

## Hardware You Need

| Item | Notes |
|------|-------|
| Raspberry Pi 4 (any RAM) | 2 GB is plenty |
| microSD card ≥ 8 GB | Class 10 or better |
| USB-C power supply | Official Pi PSU recommended |
| **2× Ethernet cables** | Pi→router and Pi→switch |
| USB-to-Ethernet adapter | For the second LAN port (`eth1`) |
| Ethernet switch | For LAN side (can be cheap unmanaged) |

> **Alternative**: If you use the Pi's built-in Wi-Fi (`wlan0`) as the LAN access point,
> you only need one Ethernet cable (WAN side). Run `pi4_gateway.sh --wifi-ap` in that case.

---

## Step 1 — Flash Raspberry Pi OS

1. Download [Raspberry Pi Imager](https://www.raspberrypi.com/software/).
2. Flash **Raspberry Pi OS Lite (64-bit)** (no desktop needed).
3. Before writing, click the ⚙ gear icon and:
   - Enable SSH
   - Set hostname: `pi-firewall`
   - Set username: `pi` and a strong password
4. Insert the card, connect a keyboard+monitor (first boot) or SSH in.

---

## Step 2 — Connect Cables

```
WAN Router port  ──[cable]──► Pi eth0
Pi eth1          ──[cable]──► LAN Switch port 1
LAN Switch       ──[cables]──► Chromecast, TV, etc.
```

---

## Step 3 — Copy the Blocker Software to the Pi

From your development machine (or clone directly on the Pi):

```bash
# Option A: copy via scp
scp -r /path/to/block_chromecast pi@pi-firewall.local:/home/pi/

# Option B: clone on the Pi
ssh pi@pi-firewall.local
git clone https://github.com/your-repo/block_chromecast.git
cd block_chromecast
```

---

## Step 4 — Run the Setup Script

```bash
ssh pi@pi-firewall.local
cd ~/block_chromecast
sudo bash pi4_gateway.sh
```

The script will:

1. Update the OS
2. Install all dependencies (`python3`, `iptables`, `dnsmasq`, `nmap`, etc.)
3. Configure `eth1` as the LAN interface with IP `10.42.0.1`
4. Enable **IP forwarding** (makes the Pi route packets)
5. Set up **NAT masquerading** (LAN devices share the WAN IP)
6. Apply **Chromecast-specific WAN-blocking rules** in iptables
7. Configure **dnsmasq** as DHCP + DNS server for the LAN  
   (DNS-level blocking of Google Cast domains is included)
8. Install the blocker as a **systemd service** (auto-starts on boot)
9. Start the **Web UI** on port 8080

### Options

```bash
# Use Pi's built-in WiFi as the LAN AP (no USB adapter needed)
sudo bash pi4_gateway.sh --wifi-ap

# Custom interface names
sudo bash pi4_gateway.sh --wan-iface eth0 --lan-iface enx001122334455

# Custom subnet
sudo bash pi4_gateway.sh --subnet 10.0.1.0/24 --gw-ip 10.0.1.1

# Custom web UI port
sudo bash pi4_gateway.sh --ui-port 9090
```

---

## Step 5 — Open the Web UI

After the script finishes:

```
http://10.42.0.1:8080
```

(or whatever IP/hostname your Pi has on the LAN side)

The UI gives you:
- **Terminal tab** — live streaming output from all running tasks
- **Status tab** — which devices are protected and which iptables rules are active
- **Config tab** — edit `config.yaml` in the browser
- **Logs tab** — application log with auto-refresh
- **iptables tab** — full live iptables ruleset

---

## Step 6 — Discover and Protect Chromecasts

1. Connect your Chromecast to the **LAN switch** (the Pi side, not the router side).
2. Power it on — it will get an IP from the Pi's DHCP server (e.g. `10.42.0.1`).
3. In the Web UI, click **Discover Devices** in the sidebar.
4. Add the discovered IP to `config.yaml` (Config tab).
5. Click **Protect All Devices**.

Or from the terminal on the Pi:

```bash
cd /opt/chromecast_blocker

# Discover
python3 chromecast_blocker.py discover

# Full protect a single device
sudo python3 chromecast_blocker.py full-protect --ip 10.42.0.1

# Protect all devices in config.yaml
sudo python3 advanced_blocker.py protect-all

# Start continuous monitoring in background
sudo python3 advanced_blocker.py monitor &

# Watch live status
python3 status_monitor.py
```

---

## Using the Web UI and Terminal in Parallel

The UI server and terminal work **independently and in parallel**:

| Method | How |
|--------|-----|
| Web UI | Open `http://<pi-ip>:8080` — all output streams to the browser terminal |
| SSH terminal | `ssh pi@pi-firewall.local` — run any command normally |
| Both at once | Works fine — each process streams its own output to the UI terminal tab |
| Kill a task from UI | Click ✕ next to any running task in the sidebar |
| Kill a task from shell | `kill <pid>` or `Ctrl-C` |

When you run a command from the Web UI, a **new terminal tab opens automatically**
so parallel tasks don't mix their output.

---

## Service Management

```bash
# View service status
systemctl status chromecast-blocker
systemctl status chromecast-ui

# View live logs
journalctl -fu chromecast-blocker
journalctl -fu chromecast-ui

# Restart after config changes
systemctl restart chromecast-blocker
systemctl restart chromecast-ui

# Stop everything
systemctl stop chromecast-blocker chromecast-ui

# Disable autostart
systemctl disable chromecast-blocker chromecast-ui
```

---

## What Gets Blocked

| Category | Details |
|----------|---------|
| **Google cloud telemetry** | All TCP 80/443 to Google IP ranges (216.239.x.x, 142.250.x.x, etc.) |
| **Cast cloud relay** | TCP port 8443 (Google Cast signalling) |
| **Tracking DNS** | `googleapis.com`, `cast.google.com`, `eureka.gvt1.com` and others resolved to `#` (black-hole) |
| **Google Public DNS bypass** | 8.8.8.8 and 8.8.4.4 are blocked — Pi forces DNS through Quad9 |
| **NTP tracking** | Google NTP servers (216.239.35.x) blocked |
| **Eavesdropping ports** | TCP 80/443, UDP 5353, 1900 outbound to WAN from Chromecast IP |
| **MITM / IP spoofing** | `iptables` `INVALID` state drop + addrtype checks |

Local streaming (phone→Chromecast on same LAN) continues to work normally.

---

## Verify the Blocking Works

```bash
# From the Pi — check iptables rules for a Chromecast IP
sudo iptables -L -n | grep 10.42.0.1

# From the Pi — run a tcpdump to watch what Chromecast sends
sudo tcpdump -i eth1 host 10.42.0.1 -n

# Try to reach Google from the Chromecast's IP (should fail)
# (run from a device with the Chromecast IP)
curl --interface 10.42.0.1 https://google.com --max-time 5
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Devices not getting DHCP | Check `systemctl status dnsmasq`, verify `eth1` has IP `10.42.0.1` |
| No internet on LAN devices | Check `sysctl net.ipv4.ip_forward` = 1, verify NAT rule: `iptables -t nat -L` |
| Web UI not loading | Check `systemctl status chromecast-ui`, try `curl http://localhost:8080` on Pi |
| Chromecast not discovered | Make sure it's on the LAN side (eth1), run `nmap -p 8008,8009 10.42.0.0/24` |
| Rules lost after reboot | Run `sudo netfilter-persistent save` then `sudo netfilter-persistent reload` |
| iptables: Permission denied | The blocker services run as root — check service user in systemd unit |

---

## Security Notes

- The Pi itself should be **physically secured** — anyone with physical access can modify the firewall.
- Change the default SSH password and consider key-based auth only.
- The Web UI has no authentication by default. Consider adding a reverse proxy with HTTP basic auth if the Pi is on a shared network.
- Regularly update the Pi: `sudo apt-get update && sudo apt-get upgrade`.
