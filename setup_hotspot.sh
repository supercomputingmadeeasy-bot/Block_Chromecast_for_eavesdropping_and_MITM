#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  setup_hotspot.sh — Persistent WiFi Hotspot for Chromecast blocking     ║
# ║                                                                          ║
# ║  Creates a WPA2 access point on wlan0 that survives reboots:            ║
# ║    SSID     : chromecast_blocked  (default, configurable below)         ║
# ║    Password : 12345678            (default, change with --pass or later ║
# ║               via:  sudo bash change_hotspot_password.sh <new_pass>)    ║
# ║                                                                          ║
# ║  Usage:                                                                  ║
# ║    sudo bash setup_hotspot.sh [--ssid NAME] [--pass PASS]               ║
# ║                   [--iface wlan0] [--ip 10.42.0.1] [--channel 6]        ║
# ║                                                                          ║
# ║  Supports both:                                                          ║
# ║    • NetworkManager (Raspberry Pi OS Bookworm / modern Bullseye)        ║
# ║    • Legacy hostapd + dnsmasq  (Buster / non-NM setups)                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────
SSID="chromecast_blocked"
PASSPHRASE="12345678"
IFACE="wlan0"
AP_IP="10.42.0.1"
AP_NETMASK="255.255.255.0"
DHCP_START="10.42.0.10"
DHCP_END="10.42.0.200"
CHANNEL=6
NM_CON="chromecast-hotspot"

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
    --ssid)    SSID="$2";    shift 2 ;;
    --pass)    PASSPHRASE="$2"; shift 2 ;;
    --iface)   IFACE="$2";   shift 2 ;;
    --ip)      AP_IP="$2";   shift 2 ;;
    --channel) CHANNEL="$2"; shift 2 ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

# ── Validate passphrase length (WPA requires 8–63 chars) ─────────────────
PASS_LEN="${#PASSPHRASE}"
if (( PASS_LEN < 8 || PASS_LEN > 63 )); then
  error "Passphrase must be 8–63 characters (got ${PASS_LEN})"
fi

# ── Root check ────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run this script with sudo"

# ── Interface check ───────────────────────────────────────────────────────
if ! ip link show "${IFACE}" &>/dev/null; then
  error "Interface '${IFACE}' not found. Use --iface to specify the correct interface."
fi

echo ""
echo -e "${BOLD}╔═════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   Chromecast Hotspot Setup                         ║${NC}"
echo -e "${BOLD}╚═════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Interface  : ${CYAN}${IFACE}${NC}"
echo -e "  SSID       : ${CYAN}${SSID}${NC}"
echo -e "  Password   : ${CYAN}${PASSPHRASE}${NC}  ← change later with change_hotspot_password.sh"
echo -e "  Pi IP      : ${CYAN}${AP_IP}${NC}"
echo -e "  DHCP range : ${CYAN}${DHCP_START} – ${DHCP_END}${NC}"
echo -e "  Channel    : ${CYAN}${CHANNEL}${NC}"
echo ""
read -rp "Continue? [y/N] " ans
[[ "${ans,,}" == "y" ]] || { info "Aborted."; exit 0; }

# ═══════════════════════════════════════════════════════════════════════════
# Detect whether NetworkManager is running
USE_NM=false
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
  USE_NM=true
fi

# ═══════════════════════════════════════════════════════════════════════════
if [[ "$USE_NM" == "true" ]]; then
  # ─────────────────────────────────────────────────────────────────────────
  # NETWORKMANAGER PATH (Raspberry Pi OS Bookworm and modern Bullseye)
  # nmcli creates a persistent connection profile that auto-starts on boot.
  # ─────────────────────────────────────────────────────────────────────────
  step "Configuring hotspot via NetworkManager"

  # Remove any existing connection with the same name
  if nmcli con show "${NM_CON}" &>/dev/null; then
    info "Removing existing '${NM_CON}' connection..."
    nmcli con delete "${NM_CON}" > /dev/null
  fi

  # Write the NM keyfile directly.
  # nmcli con add with psk-flags=0 does NOT reliably write the PSK into the
  # system keyfile — NM may agent-manage it and lose it on reboot.
  # Writing the .nmconnection file directly guarantees the PSK persists.
  NM_KEYFILE="/etc/NetworkManager/system-connections/${NM_CON}.nmconnection"
  mkdir -p /etc/NetworkManager/system-connections

  # Generate a stable UUID from the SSID so re-runs are idempotent
  CONN_UUID=$(python3 -c "import uuid; print(uuid.uuid5(uuid.NAMESPACE_DNS, '${SSID}'))" 2>/dev/null \
              || cat /proc/sys/kernel/random/uuid)

  info "Writing NM keyfile: ${NM_KEYFILE}"
  cat > "${NM_KEYFILE}" <<NMCON_EOF
[connection]
id=${NM_CON}
uuid=${CONN_UUID}
type=wifi
autoconnect=true
autoconnect-priority=100
permissions=

[wifi]
band=bg
channel=${CHANNEL}
mode=ap
ssid=${SSID}

[wifi-security]
key-mgmt=wpa-psk
psk=${PASSPHRASE}
psk-flags=0

[ipv4]
method=shared
address1=${AP_IP}/24

[ipv6]
method=disabled
addr-gen-mode=stable-privacy
NMCON_EOF

  # Keyfile must be root-only — NM refuses to load world-readable connection files
  chmod 600 "${NM_KEYFILE}"
  chown root:root "${NM_KEYFILE}"
  success "Keyfile written (PSK stored on-disk, not agent-managed)"

  # Reload NM connection list so it picks up the new file
  nmcli con reload
  sleep 1

  # Bring it up immediately
  info "Activating hotspot..."
  nmcli con up "${NM_CON}" || warn "Could not activate now (will come up on next boot)"

  success "NetworkManager hotspot configured — PSK will persist across reboots"

  # NM's built-in 'shared' mode provides dnsmasq DHCP — no extra setup needed.

else
  # ─────────────────────────────────────────────────────────────────────────
  # LEGACY PATH — hostapd + dnsmasq (older Pi OS / non-NM setups)
  # ─────────────────────────────────────────────────────────────────────────
  step "Installing hostapd and dnsmasq"
  apt-get update -qq
  apt-get install -y -qq hostapd dnsmasq

  # ── Stop services while we configure ─────────────────────────────────────
  systemctl stop hostapd 2>/dev/null || true
  systemctl stop dnsmasq  2>/dev/null || true

  # ── Unmanage wlan0 from dhcpcd ────────────────────────────────────────────
  step "Assigning static IP to ${IFACE}"
  if [[ -f /etc/dhcpcd.conf ]]; then
    # Remove any existing static block for this interface
    sed -i "/^interface ${IFACE}/,/^$/d" /etc/dhcpcd.conf
    cat >> /etc/dhcpcd.conf <<DHCPCD_EOF

interface ${IFACE}
    static ip_address=${AP_IP}/24
    nohook wpa_supplicant
DHCPCD_EOF
  else
    # Fallback: /etc/network/interfaces.d/
    mkdir -p /etc/network/interfaces.d
    cat > /etc/network/interfaces.d/hotspot.conf <<IFACE_EOF
allow-hotplug ${IFACE}
iface ${IFACE} inet static
    address ${AP_IP}
    netmask ${AP_NETMASK}
IFACE_EOF
  fi

  # Apply static IP immediately
  ip addr flush dev "${IFACE}" 2>/dev/null || true
  ip addr add "${AP_IP}/24" dev "${IFACE}"
  ip link set "${IFACE}" up

  success "Static IP ${AP_IP} set on ${IFACE}"

  # ── Configure hostapd ─────────────────────────────────────────────────────
  step "Writing /etc/hostapd/hostapd.conf"
  mkdir -p /etc/hostapd
  cat > /etc/hostapd/hostapd.conf <<HOSTAPD_EOF
interface=${IFACE}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=${CHANNEL}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${PASSPHRASE}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
country_code=US
HOSTAPD_EOF

  # Point hostapd at its config file
  sed -i 's|^#*DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

  systemctl unmask hostapd
  systemctl enable hostapd
  success "hostapd configured"

  # ── Configure dnsmasq ─────────────────────────────────────────────────────
  step "Writing /etc/dnsmasq.conf"

  # Preserve original if not already backed up
  [[ -f /etc/dnsmasq.conf.orig ]] || cp /etc/dnsmasq.conf /etc/dnsmasq.conf.orig 2>/dev/null || true

  # Disable systemd-resolved stub listener so it does not compete on port 53
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/no-stub.conf <<RESOLVE_EOF
[Resolve]
DNSStubListener=no
RESOLVE_EOF
    systemctl restart systemd-resolved
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  fi

  cat > /etc/dnsmasq.conf <<DNSMASQ_EOF
# dnsmasq — Chromecast hotspot DHCP + DNS
interface=${IFACE}
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},24h
dhcp-option=option:router,${AP_IP}
dhcp-option=option:dns-server,${AP_IP}

# Block Google DNS hard-coded into Chromecast
address=/googleapis.com/#
address=/clients.google.com/#
address=/connectivitycheck.gstatic.com/#
address=/eureka.gvt1.com/#
address=/cast.google.com/#
address=/chromecast.google.com/#

# Upstream DNS (privacy-respecting)
server=9.9.9.9
server=149.112.112.112

log-queries
log-facility=/var/log/dnsmasq.log
DNSMASQ_EOF

  touch /var/log/dnsmasq.log
  chmod 644 /var/log/dnsmasq.log

  systemctl enable dnsmasq
  success "dnsmasq configured"

  # ── Enable IP forwarding ──────────────────────────────────────────────────
  step "Enabling IP forwarding"
  sed -i 's|^#*net.ipv4.ip_forward.*|net.ipv4.ip_forward=1|' /etc/sysctl.conf
  grep -q "net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  success "IP forwarding enabled"

  # ── Start services ────────────────────────────────────────────────────────
  step "Starting services"
  systemctl start hostapd || {
    echo "[ERR] hostapd failed — check: journalctl -xeu hostapd.service"
    journalctl -xeu hostapd.service --no-pager | tail -20
    exit 1
  }
  systemctl start dnsmasq || {
    echo "[ERR] dnsmasq failed — check: journalctl -xeu dnsmasq.service"
    journalctl -xeu dnsmasq.service --no-pager | tail -20
    exit 1
  }
  success "hostapd and dnsmasq running"

fi   # end legacy path

# ═══════════════════════════════════════════════════════════════════════════
# Configure Pi user autologin so desktop autostart fires on every reboot
step "Configuring user autologin"

AUTOLOGIN_USER="${SUDO_USER:-}"
# If SUDO_USER is empty (e.g. run as root directly) fall back to 'pi' or 'jorgen-larsen'
if [[ -z "$AUTOLOGIN_USER" ]]; then
  if id "jorgen-larsen" &>/dev/null; then
    AUTOLOGIN_USER="jorgen-larsen"
  elif id "pi" &>/dev/null; then
    AUTOLOGIN_USER="pi"
  else
    AUTOLOGIN_USER=$(getent passwd 1000 | cut -d: -f1)
  fi
fi

if [[ -n "$AUTOLOGIN_USER" ]]; then
  # ── Desktop autologin (lightdm — used by Raspberry Pi OS) ─────────────
  if command -v lightdm &>/dev/null || [[ -d /etc/lightdm ]]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/20-autologin.conf <<AUTOLOGIN_EOF
[Seat:*]
autologin-user=${AUTOLOGIN_USER}
autologin-user-timeout=0
AUTOLOGIN_EOF
    success "lightdm autologin configured for '${AUTOLOGIN_USER}'"
  fi

  # ── Console autologin (getty — fallback / headless Pi) ────────────────
  mkdir -p /etc/systemd/system/getty@tty1.service.d
  cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<GETTY_EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin ${AUTOLOGIN_USER} --noclear %I \$TERM
GETTY_EOF
  systemctl daemon-reload
  success "Console autologin configured for '${AUTOLOGIN_USER}'"

  # ── Install desktop autostart entry ───────────────────────────────────
  SCRIPT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
  AUTOSTART_DIR="/home/${AUTOLOGIN_USER}/.config/autostart"
  mkdir -p "${AUTOSTART_DIR}"
  cp "${SCRIPT_DIR}/chromecast-autostart.desktop" "${AUTOSTART_DIR}/chromecast-autostart.desktop"
  chown -R "${AUTOLOGIN_USER}:${AUTOLOGIN_USER}" "/home/${AUTOLOGIN_USER}/.config"
  success "Autostart entry installed → ${AUTOSTART_DIR}/chromecast-autostart.desktop"

else
  warn "Could not determine autologin user — skipping autologin setup"
  warn "Run manually:  sudo raspi-config  → System Options → Boot/Auto Login"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Write a persistent config file so change_hotspot_password.sh knows the setup
step "Saving hotspot config"
mkdir -p /etc/chromecast_blocker
cat > /etc/chromecast_blocker/hotspot.conf <<CONFIG_EOF
# Chromecast Blocker — Hotspot configuration
# Edit this file and run: sudo bash /etc/chromecast_blocker/apply_hotspot.sh
SSID="${SSID}"
PASSPHRASE="${PASSPHRASE}"
IFACE="${IFACE}"
AP_IP="${AP_IP}"
CHANNEL="${CHANNEL}"
NM_CON="${NM_CON}"
USE_NM="${USE_NM}"
CONFIG_EOF
chmod 600 /etc/chromecast_blocker/hotspot.conf   # password is sensitive

success "Config saved to /etc/chromecast_blocker/hotspot.conf"

# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  Hotspot setup complete!                            ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  WiFi SSID : ${BOLD}${SSID}${NC}"
echo -e "  Password  : ${BOLD}${PASSPHRASE}${NC}"
echo -e "  Pi IP     : ${BOLD}${AP_IP}${NC}"
echo ""
echo -e "  To change the password at any time:"
echo -e "    ${CYAN}sudo bash $(dirname "$(realpath "$0")")/change_hotspot_password.sh <new_password>${NC}"
echo ""
echo -e "  The hotspot will restart automatically on every reboot."
echo ""
