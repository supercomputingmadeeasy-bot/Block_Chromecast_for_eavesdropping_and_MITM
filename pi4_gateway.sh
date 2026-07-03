#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Raspberry Pi 4 — WAN Gateway & Chromecast Privacy Firewall Setup       ║
# ║                                                                          ║
# ║  Network topology:                                                       ║
# ║                                                                          ║
# ║   Internet ──► WAN Router ──► [ Pi 4 eth0 ]                             ║
# ║                                [ Pi 4 eth1 ] ──► LAN Switch             ║
# ║                                                       └──► Chromecast    ║
# ║                                                       └──► Other devices ║
# ║                                                                          ║
# ║  The Pi 4 sits between your WAN router and your local devices.           ║
# ║  ALL Chromecast spy/telemetry traffic is blocked at this chokepoint.     ║
# ║                                                                          ║
# ║  Requirements:                                                           ║
# ║    • Raspberry Pi 4 with Raspberry Pi OS (64-bit recommended)            ║
# ║    • eth0  → cable to WAN router  (gets IP via DHCP)                    ║
# ║    • eth1  → cable to LAN switch  (USB-Ethernet adapter or second NIC)  ║
# ║      OR: use built-in WiFi (wlan0) as the LAN access point              ║
# ║                                                                          ║
# ║  Usage:  sudo bash pi4_gateway.sh [--wifi-ap] [--lan-iface eth1]        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Config defaults (override with CLI args) ──────────────────────────────
WAN_IFACE="eth0"        # Interface connected to your WAN router
LAN_IFACE="eth1"        # Interface connected to your local switch/devices
LAN_SUBNET="10.42.0.0/24"
LAN_GW_IP="10.42.0.1"
DHCP_RANGE_START="10.42.0.10"
DHCP_RANGE_END="10.42.0.200"
WIFI_AP=false           # Set true to use wlan0 as LAN AP instead of eth1
BLOCKER_DIR="/opt/chromecast_blocker"
BLOCKER_USER="${SUDO_USER:-$(logname 2>/dev/null || echo pi)}"
UI_PORT=8080

# ── Colour helpers ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }
step()    { echo -e "\n${BOLD}═══ $* ═══${NC}"; }

# ── Parse args ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --wifi-ap)    WIFI_AP=true; LAN_IFACE="wlan0"; shift ;;
    --nm-hotspot) WIFI_AP=true; LAN_IFACE="wlan0"; NM_MANAGED=true; shift ;;
    --lan-iface)  LAN_IFACE="$2"; shift 2 ;;
    --wan-iface)  WAN_IFACE="$2"; shift 2 ;;
    --subnet)     LAN_SUBNET="$2"; shift 2 ;;
    --gw-ip)      LAN_GW_IP="$2"; shift 2 ;;
    --ui-port)    UI_PORT="$2"; shift 2 ;;
    --dir)        BLOCKER_DIR="$2"; shift 2 ;;
    --user)       BLOCKER_USER="$2"; shift 2 ;;
    *) warn "Unknown arg: $1"; shift ;;
  esac
done

# ── Auto-detect NetworkManager-managed hotspot ────────────────────────────
# If NM already owns wlan0 as a shared AP, skip hostapd + standalone dnsmasq
if [[ "${WIFI_AP}" == "true" && "${NM_MANAGED:-false}" != "true" ]]; then
  if nmcli -t -f DEVICE,TYPE,STATE dev status 2>/dev/null | grep -q "^wlan0:wifi:connected"; then
    NM_MANAGED=true
    info "Detected NetworkManager hotspot on wlan0 — skipping hostapd/dnsmasq setup"
  fi
fi

# ── Root check ────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run this script with sudo"

# ── Interface validation ──────────────────────────────────────────────────
ALL_IFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')
if ! ip link show "${WAN_IFACE}" &>/dev/null; then
  echo "[ERR]   WAN interface '${WAN_IFACE}' not found."
  echo "        Available interfaces: $(echo $ALL_IFACES | tr '\n' ' ')"
  echo "        Re-run with:  sudo bash $0 --wan-iface <iface>"
  exit 1
fi
if ! ip link show "${LAN_IFACE}" &>/dev/null; then
  echo "[ERR]   LAN interface '${LAN_IFACE}' not found."
  echo "        Available interfaces: $(echo $ALL_IFACES | tr '\n' ' ')"
  echo "        Re-run with:  sudo bash $0 --lan-iface <iface>"
  echo ""
  echo "        Tip: a second USB-Ethernet adapter or a USB-C dock adapter"
  echo "             will appear here once plugged in (e.g. enx..., usb0)."
  exit 1
fi
if [[ "${WAN_IFACE}" == "${LAN_IFACE}" ]]; then
  error "WAN and LAN interfaces must be different (both set to '${WAN_IFACE}')"
fi

# ── OS check ─────────────────────────────────────────────────────────────
if ! grep -qi "raspberry\|debian\|ubuntu" /etc/os-release 2>/dev/null; then
  warn "This script is tested on Raspberry Pi OS / Debian. Proceeding anyway."
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Pi 4 WAN Gateway + Chromecast Firewall Setup   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  WAN interface  : ${CYAN}${WAN_IFACE}${NC}"
echo -e "  LAN interface  : ${CYAN}${LAN_IFACE}${NC}"
echo -e "  LAN subnet     : ${CYAN}${LAN_SUBNET}${NC}"
echo -e "  Pi LAN IP      : ${CYAN}${LAN_GW_IP}${NC}"
echo -e "  Blocker dir    : ${CYAN}${BLOCKER_DIR}${NC}"
echo -e "  Web UI port    : ${CYAN}${UI_PORT}${NC}"
echo ""
read -rp "Continue? [y/N] " ans
[[ "${ans,,}" == "y" ]] || { info "Aborted."; exit 0; }

# ═══════════════════════════════════════════════════════════════════════════
step "1. Update system packages"
apt-get update -qq
apt-get upgrade -y -qq
success "System updated"

# ═══════════════════════════════════════════════════════════════════════════
step "2. Install required packages"
PACKAGES="python3 python3-pip python3-venv iptables iptables-persistent
          nmap avahi-utils avahi-daemon tcpdump arptables dnsmasq git curl"
if [[ "$WIFI_AP" == "true" && "${NM_MANAGED:-false}" != "true" ]]; then
  PACKAGES="$PACKAGES hostapd"
fi
# shellcheck disable=SC2086
apt-get install -y -qq $PACKAGES
success "Packages installed"

# ═══════════════════════════════════════════════════════════════════════════
step "3. Configure LAN interface (${LAN_IFACE})"

if [[ "$WIFI_AP" == "true" && "${NM_MANAGED:-false}" != "true" ]]; then
  # WiFi AP mode — standalone hostapd (no NetworkManager)
  info "Configuring ${LAN_IFACE} as WiFi access point..."

  cat > /etc/hostapd/hostapd.conf <<EOF
interface=${LAN_IFACE}
driver=nl80211
ssid=chromecast_blocked
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=12345678
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
country_code=US
EOF
  sed -i 's|#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
  warn "WiFi AP SSID=chromecast_blocked, password=12345678 — change with: sudo bash change_hotspot_password.sh <new_pass>"

elif [[ "$WIFI_AP" == "true" && "${NM_MANAGED:-false}" == "true" ]]; then
  # NetworkManager manages the AP — nothing to configure here
  info "Skipping hostapd: NetworkManager controls ${LAN_IFACE}"

else
  # Wired LAN interface — assign static IP
  info "Setting static IP ${LAN_GW_IP} on ${LAN_IFACE}..."

  # Use /etc/network/interfaces.d for the LAN interface
  mkdir -p /etc/network/interfaces.d
  cat > /etc/network/interfaces.d/lan.conf <<EOF
auto ${LAN_IFACE}
iface ${LAN_IFACE} inet static
    address ${LAN_GW_IP}
    netmask 255.255.255.0
EOF
fi

success "LAN interface configured"

# ═══════════════════════════════════════════════════════════════════════════
step "4. Enable IP forwarding"
# Make it persistent
sed -i 's|^#*net.ipv4.ip_forward.*|net.ipv4.ip_forward=1|' /etc/sysctl.conf
# Also add if not present
grep -q "net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 > /dev/null
success "IP forwarding enabled"

# ═══════════════════════════════════════════════════════════════════════════
step "4b. Tune kernel for streaming throughput"
# Streaming (DR.dk, TV2, Spotify) creates many concurrent TCP connections.
# Default conntrack table on a Pi is 8192 entries — easily exhausted, causing
# silent packet drops that appear as "connection lost" or app freezes.

SYSCTL_STREAMING=(
  # Conntrack table — allow up to 65536 simultaneous tracked connections
  "net.netfilter.nf_conntrack_max=65536"
  # TCP time-wait bucket — recycle sooner to free table slots
  "net.ipv4.tcp_max_tw_buckets=16384"
  # Reduce time a CLOSE_WAIT / FIN_WAIT connection occupies conntrack
  "net.netfilter.nf_conntrack_tcp_timeout_close_wait=10"
  "net.netfilter.nf_conntrack_tcp_timeout_fin_wait=10"
  "net.netfilter.nf_conntrack_tcp_timeout_time_wait=10"
  # Keep ESTABLISHED connections tracked longer (streaming sessions can be idle briefly)
  "net.netfilter.nf_conntrack_tcp_timeout_established=1800"
  # UDP conntrack (DNS replies): keep short so table stays clean
  "net.netfilter.nf_conntrack_udp_timeout=10"
  "net.netfilter.nf_conntrack_udp_timeout_stream=30"
  # Increase socket receive/send buffers for better throughput on 1080p/4K
  "net.core.rmem_max=16777216"
  "net.core.wmem_max=16777216"
  "net.ipv4.tcp_rmem=4096 87380 16777216"
  "net.ipv4.tcp_wmem=4096 65536 16777216"
)

for param in "${SYSCTL_STREAMING[@]}"; do
  key="${param%%=*}"
  val="${param##*=}"
  # Apply immediately (ignore errors — some params need nf_conntrack loaded first)
  sysctl -w "${key}=${val}" > /dev/null 2>&1 || true
  # Persist across reboots
  grep -q "^${key}" /etc/sysctl.conf \
    && sed -i "s|^${key}.*|${key}=${val}|" /etc/sysctl.conf \
    || echo "${key}=${val}" >> /etc/sysctl.conf
done

# hashsize should be half of nf_conntrack_max for good performance
if [[ -f /sys/module/nf_conntrack/parameters/hashsize ]]; then
  echo 32768 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi

success "Kernel streaming tuning applied"

# ═══════════════════════════════════════════════════════════════════════════
step "5. Configure NAT (masquerading) and base firewall rules"

# Flush existing rules first
iptables -F
iptables -t nat -F
iptables -X 2>/dev/null || true

# Default policies
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

# NAT: masquerade LAN traffic going out WAN
iptables -t nat -A POSTROUTING -o "${WAN_IFACE}" -j MASQUERADE

# Allow established/related traffic back in
iptables -A FORWARD -i "${WAN_IFACE}" -o "${LAN_IFACE}" \
  -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "${LAN_IFACE}" -o "${WAN_IFACE}" -j ACCEPT

# Allow SSH to the Pi itself
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# Allow web UI
iptables -A INPUT -p tcp --dport "${UI_PORT}" -j ACCEPT
# Allow DNS queries to the Pi (dnsmasq)
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
# Allow DHCP
iptables -A INPUT -p udp --dport 67:68 -j ACCEPT
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
# Allow established
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

success "Base NAT and firewall rules applied"

# ═══════════════════════════════════════════════════════════════════════════
step "6. Apply Chromecast WAN-blocking rules"

# Block Chromecast from sending ANY traffic to the public internet.
# These rules block WAN-bound forwarded packets from the Chromecast subnets.
# The chromecast_blocker.py will add more specific per-device rules later.

BLOCK_DOMAINS=(
  "8.8.8.8" "8.8.4.4"                         # Google Public DNS (Chromecast hardcoded)
  "216.239.0.0/19"                              # Google infrastructure
  "142.250.0.0/15"                              # Google
  "172.217.0.0/16"                              # Google
  "74.125.0.0/16"                               # Google
)

for net in "${BLOCK_DOMAINS[@]}"; do
  # Block Chromecast-initiated outbound connections to Google WAN IPs
  iptables -A FORWARD -i "${LAN_IFACE}" -o "${WAN_IFACE}" \
    -d "${net}" -p tcp --dport 443 -j DROP 2>/dev/null || true
  iptables -A FORWARD -i "${LAN_IFACE}" -o "${WAN_IFACE}" \
    -d "${net}" -p tcp --dport 80  -j DROP 2>/dev/null || true
done

# Block Chromecast cloud signalling ports regardless of destination
# (will be refined by per-device rules once Chromecast IPs are known)
# Port 8443 = Google Cast cloud relay
iptables -A FORWARD -i "${LAN_IFACE}" -o "${WAN_IFACE}" \
  -p tcp --dport 8443 -j DROP
# Block Chromecast NTP abuse (prevents time-sync used for tracking)
iptables -A FORWARD -i "${LAN_IFACE}" -o "${WAN_IFACE}" \
  -p udp --dport 123 -d 216.239.35.0/24 -j DROP

success "Chromecast WAN-blocking base rules applied"

# ═══════════════════════════════════════════════════════════════════════════
step "7. Configure DNS (DHCP + Chromecast hostname blocking)"

if [[ "${NM_MANAGED:-false}" == "true" ]]; then
  # NetworkManager's internal dnsmasq handles DHCP — inject our block rules
  # into its drop-in dir so it picks them up on next restart.
  info "Injecting Chromecast DNS blocks into NetworkManager dnsmasq config..."
  mkdir -p /etc/NetworkManager/dnsmasq-shared.d
  cat > /etc/NetworkManager/dnsmasq-shared.d/chromecast-blocks.conf <<EOF
# Chromecast / Google telemetry DNS blocks
# Managed by pi4_gateway.sh — do not edit manually
# NOTE: Google ad domains (doubleclick.net, googlesyndication.com,
# googleadservices.com, gstaticadssl.l.google.com) are intentionally NOT
# blocked here so that Spotify Free works on non-Chromecast clients.
# The Chromecast is still protected via iptables (gstatic.com string-match
# on DNS from Chromecast IP) and AdGuard DNS redirect.
address=/googleapis.com/#
address=/clients.google.com/#
address=/connectivitycheck.gstatic.com/#
address=/clients3.google.com/#
address=/www3.l.google.com/#
address=/eureka.gvt1.com/#
address=/cast.google.com/#
address=/chromecast.google.com/#
# Upstream DNS (Quad9 — privacy-focused)
server=9.9.9.9
server=149.112.112.112
EOF
  # Tell NM to restart the shared connection so dnsmasq reloads
  NM_CON=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null \
            | grep ":${LAN_IFACE}$" | cut -d: -f1 | head -1)
  if [[ -n "$NM_CON" ]]; then
    nmcli con down "$NM_CON" && nmcli con up "$NM_CON" \
      && success "NetworkManager hotspot restarted with Chromecast DNS blocks" \
      || warn "Could not restart NM connection '${NM_CON}' — reboot to apply DNS blocks"
  else
    warn "No active NM connection found on ${LAN_IFACE} — reboot to apply DNS blocks"
  fi
else
  # Standalone dnsmasq
  systemctl stop dnsmasq 2>/dev/null || true

  # Disable systemd-resolved stub listener so it doesn't occupy port 53
  if systemctl is-active --quiet systemd-resolved; then
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/no-stub.conf <<EOF
[Resolve]
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  fi

  touch /var/log/dnsmasq.log
  chmod 644 /var/log/dnsmasq.log

  cat > /etc/dnsmasq.conf <<EOF
# dnsmasq config — Pi 4 LAN gateway
interface=${LAN_IFACE}
bind-interfaces

dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},24h
dhcp-option=option:router,${LAN_GW_IP}
dhcp-option=option:dns-server,${LAN_GW_IP}

# Block Google DNS / Chromecast telemetry
# NOTE: Google ad domains (doubleclick.net, googlesyndication.com,
# googleadservices.com, gstaticadssl.l.google.com) are intentionally NOT
# blocked here so that Spotify Free works on non-Chromecast clients.
# The Chromecast is still protected via iptables (gstatic.com string-match
# on DNS from Chromecast IP) and AdGuard DNS redirect.
address=/googleapis.com/#
address=/clients.google.com/#
address=/connectivitycheck.gstatic.com/#
address=/clients3.google.com/#
address=/www3.l.google.com/#
address=/eureka.gvt1.com/#
address=/cast.google.com/#
address=/chromecast.google.com/#

server=9.9.9.9
server=149.112.112.112

log-queries
log-facility=/var/log/dnsmasq.log
EOF

  systemctl enable dnsmasq
  systemctl start  dnsmasq || { echo "[ERROR] dnsmasq failed to start — check: journalctl -xeu dnsmasq.service"; journalctl -xeu dnsmasq.service --no-pager | tail -30; exit 1; }
  success "dnsmasq configured and started"
fi

# ═══════════════════════════════════════════════════════════════════════════
step "8. Save iptables rules (persistent across reboots)"

netfilter-persistent save
success "iptables rules saved"

# ═══════════════════════════════════════════════════════════════════════════
step "9. Install Chromecast Blocker software"

# Create install directory
mkdir -p "${BLOCKER_DIR}"
chown "${BLOCKER_USER}:${BLOCKER_USER}" "${BLOCKER_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy project files
info "Copying blocker files to ${BLOCKER_DIR}..."
cp -r "${SCRIPT_DIR}"/*.py       "${BLOCKER_DIR}/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}"/*.yaml     "${BLOCKER_DIR}/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}"/*.sh       "${BLOCKER_DIR}/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}/templates"  "${BLOCKER_DIR}/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}/static"     "${BLOCKER_DIR}/" 2>/dev/null || true

mkdir -p "${BLOCKER_DIR}/logs"
chown -R "${BLOCKER_USER}:${BLOCKER_USER}" "${BLOCKER_DIR}"

# Create Python virtual environment
info "Creating Python virtual environment..."
sudo -u "${BLOCKER_USER}" python3 -m venv "${BLOCKER_DIR}/venv"
sudo -u "${BLOCKER_USER}" "${BLOCKER_DIR}/venv/bin/pip" install -q --upgrade pip
sudo -u "${BLOCKER_USER}" "${BLOCKER_DIR}/venv/bin/pip" install -q \
  flask flask-socketio eventlet psutil pyyaml netaddr

success "Chromecast Blocker software installed"

# ═══════════════════════════════════════════════════════════════════════════
step "10. Install systemd services"

# ── Service 1: advanced_blocker (protection daemon) ──────────────────────
cat > /etc/systemd/system/chromecast-blocker.service <<EOF
[Unit]
Description=Chromecast Security Blocker — Protection Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${BLOCKER_DIR}
ExecStart=${BLOCKER_DIR}/venv/bin/python3 advanced_blocker.py monitor --interval 60
Restart=on-failure
RestartSec=10
StandardOutput=append:${BLOCKER_DIR}/logs/blocker.log
StandardError=append:${BLOCKER_DIR}/logs/blocker.log

[Install]
WantedBy=multi-user.target
EOF

# ── Service 2: ui_server (web control panel) ─────────────────────────────
cat > /etc/systemd/system/chromecast-ui.service <<EOF
[Unit]
Description=Chromecast Blocker Web UI
After=network.target chromecast-blocker.service

[Service]
Type=simple
User=root
WorkingDirectory=${BLOCKER_DIR}
ExecStart=${BLOCKER_DIR}/venv/bin/python3 ui_server.py --host 0.0.0.0 --port ${UI_PORT}
Restart=on-failure
RestartSec=5
StandardOutput=append:${BLOCKER_DIR}/logs/ui_server.log
StandardError=append:${BLOCKER_DIR}/logs/ui_server.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable chromecast-blocker.service
systemctl enable chromecast-ui.service
systemctl start  chromecast-blocker.service
systemctl start  chromecast-ui.service

success "Systemd services installed and started"

# ═══════════════════════════════════════════════════════════════════════════
step "11. Enable WiFi AP (if selected)"

if [[ "$WIFI_AP" == "true" ]]; then
  systemctl unmask  hostapd
  systemctl enable  hostapd
  systemctl restart hostapd
  success "WiFi AP started (SSID: PiFirewall)"
fi

# ═══════════════════════════════════════════════════════════════════════════
step "12. Sudoers — allow blocker to run iptables and python without password"

SUDOERS_FILE="/etc/sudoers.d/chromecast-blocker"
cat > "${SUDOERS_FILE}" <<EOF
# Allow chromecast-blocker to manage firewall rules without a password prompt
root ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/iptables-save, /sbin/iptables-restore
root ALL=(ALL) NOPASSWD: /sbin/arptables, /usr/sbin/nmap
${BLOCKER_USER} ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/iptables-save, /sbin/iptables-restore
${BLOCKER_USER} ALL=(ALL) NOPASSWD: /sbin/arptables, /usr/sbin/nmap
# Allow running the blocker python scripts without a password prompt
# (required by startup_protect.sh which calls: sudo python3 <script>.py ...)
${BLOCKER_USER} ALL=(ALL) NOPASSWD: /usr/bin/python3
${BLOCKER_USER} ALL=(ALL) NOPASSWD: ${BLOCKER_DIR}/venv/bin/python3
EOF
chmod 440 "${SUDOERS_FILE}"
success "Sudoers configured"

# ═══════════════════════════════════════════════════════════════════════════
step "13. Configure auto-login (no password needed at boot)"

# ── Console / headless auto-login (getty on tty1) ────────────────────────
GETTY_OVERRIDE="/etc/systemd/system/getty@tty1.service.d"
mkdir -p "${GETTY_OVERRIDE}"
cat > "${GETTY_OVERRIDE}/autologin.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin ${BLOCKER_USER} --noclear %I \$TERM
EOF

# ── Desktop / LightDM auto-login (Raspberry Pi OS desktop) ──────────────
if command -v lightdm &>/dev/null || [[ -f /etc/lightdm/lightdm.conf ]]; then
  mkdir -p /etc/lightdm/lightdm.conf.d
  cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf <<EOF
[Seat:*]
autologin-user=${BLOCKER_USER}
autologin-user-timeout=0
EOF
  success "LightDM auto-login enabled for '${BLOCKER_USER}'"
fi

# ── Ensure user is in autologin group if it exists ───────────────────────
if getent group autologin &>/dev/null; then
  usermod -aG autologin "${BLOCKER_USER}"
fi

systemctl daemon-reload
success "Auto-login configured — '${BLOCKER_USER}' will log in automatically on boot"

# ═══════════════════════════════════════════════════════════════════════════
PI_IP=$(ip -4 addr show "${LAN_IFACE}" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
PI_IP="${PI_IP:-${LAN_GW_IP}}"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║             Setup Complete!                              ║${NC}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                          ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Web UI:   ${CYAN}http://${PI_IP}:${UI_PORT}${NC}"
echo -e "${GREEN}${BOLD}║${NC}  (open this in any browser on your local network)        ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                          ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Services:                                               ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    systemctl status chromecast-blocker                   ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    systemctl status chromecast-ui                        ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                          ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Logs:   ${BLOCKER_DIR}/logs/                             ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                          ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Next steps:                                             ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    1. Connect Chromecast devices to the LAN side         ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    2. Open the Web UI and click 'Discover Devices'       ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    3. Click 'Protect All Devices'                        ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    4. Monitor the Terminal tab for live output            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
warn "Reboot the Pi to ensure all network changes take full effect: sudo reboot"
