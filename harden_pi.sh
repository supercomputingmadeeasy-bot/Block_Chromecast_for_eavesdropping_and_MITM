#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Pi 4 Security Hardening                                                 ║
# ║  Layers covered:                                                         ║
# ║    • Cable MITM / ARP spoofing     (sysctl + arptables + arpwatch)      ║
# ║    • IP spoofing / bogon filtering (rp_filter + iptables bogon rules)   ║
# ║    • DDoS / flood (SYN, ICMP, UDP) (hashlimit + connlimit)              ║
# ║    • Port scan probes              (NULL/XMAS/FIN/invalid drops + LOG)  ║
# ║    • SSH brute force               (fail2ban + MaxAuthTries)             ║
# ║    • Firewall default-deny         (INPUT/FORWARD policy → DROP)        ║
# ║    • Access logging                (iptables LOG, auth.log, arpwatch)   ║
# ║    • Watchdog daemon               (pi_watchdog.py + systemd unit)      ║
# ║                                                                          ║
# ║  Run AFTER pi4_gateway.sh — this script adds on top of its rules.       ║
# ║                                                                          ║
# ║  Usage:  sudo bash harden_pi.sh [options]                               ║
# ║    --wan-iface <iface>   WAN interface         (default: eth0)          ║
# ║    --lan-iface <iface>   LAN interface         (default: eth1)          ║
# ║    --ssh-port  <port>    SSH port              (default: 22)             ║
# ║    --ssh-from  <CIDR>    Restrict SSH to CIDR  (optional, recommended)  ║
# ║    --no-autoblock        Watchdog logs only — no automatic IP blocks    ║
# ║    --dir       <path>    Blocker dir           (default: /opt/chromecast_blocker)
# ║    --user      <user>    Service user          (default: pi)             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────
WAN_IFACE="eth0"
LAN_IFACE="eth1"
SSH_PORT=22
SSH_FROM=""          # e.g. "10.42.0.0/24"  — empty = any source allowed
AUTOBLOCK=true       # watchdog auto-blocks offending IPs
BLOCKER_DIR="/opt/chromecast_blocker"
BLOCKER_USER="pi"

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
    --wan-iface)    WAN_IFACE="$2";   shift 2 ;;
    --lan-iface)    LAN_IFACE="$2";   shift 2 ;;
    --ssh-port)     SSH_PORT="$2";    shift 2 ;;
    --ssh-from)     SSH_FROM="$2";    shift 2 ;;
    --no-autoblock) AUTOBLOCK=false;  shift ;;
    --dir)          BLOCKER_DIR="$2"; shift 2 ;;
    --user)         BLOCKER_USER="$2";shift 2 ;;
    *) warn "Unknown arg: $1"; shift ;;
  esac
done

[[ $EUID -ne 0 ]] && error "Run this script with sudo"

# Validate interfaces exist
for iface in "${WAN_IFACE}" "${LAN_IFACE}"; do
  ip link show "${iface}" &>/dev/null \
    || error "Interface '${iface}' not found — check --wan-iface / --lan-iface"
done

LOG_DIR="${BLOCKER_DIR}/logs"
mkdir -p "${LOG_DIR}"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       Pi 4 Security Hardening                        ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  WAN interface  : ${CYAN}${WAN_IFACE}${NC}"
echo -e "  LAN interface  : ${CYAN}${LAN_IFACE}${NC}"
echo -e "  SSH port       : ${CYAN}${SSH_PORT}${NC}"
echo -e "  SSH allow from : ${CYAN}${SSH_FROM:-"<any>"}${NC}"
echo -e "  Auto-block IPs : ${CYAN}${AUTOBLOCK}${NC}"
echo -e "  Blocker dir    : ${CYAN}${BLOCKER_DIR}${NC}"
echo ""
read -rp "Continue? [y/N] " ans
[[ "${ans,,}" == "y" ]] || { info "Aborted."; exit 0; }

# ═══════════════════════════════════════════════════════════════════════════
step "1. Install hardening packages"

apt-get update -qq
apt-get install -y -qq \
  fail2ban \
  arpwatch \
  arptables \
  ipset \
  libpam-pwquality \
  logwatch

success "Packages installed"

# ═══════════════════════════════════════════════════════════════════════════
step "2. Kernel hardening (sysctl)"

SYSCTL_CONF="/etc/sysctl.d/99-pi-harden.conf"
cat > "${SYSCTL_CONF}" <<'EOF'
# ── Anti-MITM / ARP spoofing ──────────────────────────────────────────────
# Only respond to ARP on the interface that owns the IP (blocks ARP poisoning)
net.ipv4.conf.all.arp_ignore     = 1
net.ipv4.conf.default.arp_ignore = 1
# Always use the best local source address for ARP announcements
net.ipv4.conf.all.arp_announce     = 2
net.ipv4.conf.default.arp_announce = 2
# Do not accept gratuitous ARP from unknown hosts
net.ipv4.conf.all.arp_accept     = 0
net.ipv4.conf.default.arp_accept = 0

# ── Anti-IP-spoofing (reverse path filtering) ────────────────────────────
# Strict mode: drop packets that arrive on wrong interface for their source IP
net.ipv4.conf.all.rp_filter     = 1
net.ipv4.conf.default.rp_filter = 1

# ── Block ICMP redirect tricks (used in MITM) ────────────────────────────
net.ipv4.conf.all.accept_redirects     = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects       = 0
net.ipv4.conf.default.send_redirects   = 0
net.ipv4.conf.all.secure_redirects     = 0
net.ipv4.conf.default.secure_redirects = 0

# ── Block source-routed packets (can be used to bypass routing) ──────────
net.ipv4.conf.all.accept_source_route     = 0
net.ipv4.conf.default.accept_source_route = 0

# ── Log martian packets (spoofed/bogon source IPs) ───────────────────────
net.ipv4.conf.all.log_martians     = 1
net.ipv4.conf.default.log_martians = 1

# ── SYN flood protection ─────────────────────────────────────────────────
net.ipv4.tcp_syncookies   = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries  = 2
net.ipv4.tcp_syn_retries     = 3

# ── Smurf attack / broadcast ping protection ────────────────────────────
net.ipv4.icmp_echo_ignore_broadcasts   = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Time-wait assassination protection ───────────────────────────────────
net.ipv4.tcp_rfc1337 = 1

# ── Tighten TCP window memory limits ─────────────────────────────────────
net.ipv4.tcp_fin_timeout  = 15
net.ipv4.tcp_keepalive_time    = 300
net.ipv4.tcp_keepalive_intvl   = 30
net.ipv4.tcp_keepalive_probes  = 5

# ── ASLR (address space layout randomisation) ────────────────────────────
kernel.randomize_va_space = 2

# ── Restrict dmesg to root ────────────────────────────────────────────────
kernel.dmesg_restrict = 1

# ── Restrict kernel pointer exposure ─────────────────────────────────────
kernel.kptr_restrict = 2
EOF

sysctl --system > /dev/null
success "Kernel hardening parameters applied"

# ═══════════════════════════════════════════════════════════════════════════
step "3. iptables — HARDEN_INPUT chain (anti-scan, anti-DDoS, bogon blocking)"

# Create / flush the hardening chain
iptables -N HARDEN_INPUT 2>/dev/null || iptables -F HARDEN_INPUT

# ── Invalid packets (broken state, used by some scanners) ────────────────
iptables -A HARDEN_INPUT -m conntrack --ctstate INVALID \
  -j LOG --log-prefix "FW-INVALID: " --log-level 4
iptables -A HARDEN_INPUT -m conntrack --ctstate INVALID -j DROP

# ── NULL scan (no TCP flags set — stealth probe) ─────────────────────────
iptables -A HARDEN_INPUT -p tcp --tcp-flags ALL NONE \
  -j LOG --log-prefix "FW-NULLSCAN: " --log-level 4
iptables -A HARDEN_INPUT -p tcp --tcp-flags ALL NONE -j DROP

# ── XMAS scan (all TCP flags set — OS fingerprinting) ────────────────────
iptables -A HARDEN_INPUT -p tcp --tcp-flags ALL ALL \
  -j LOG --log-prefix "FW-XMASSCAN: " --log-level 4
iptables -A HARDEN_INPUT -p tcp --tcp-flags ALL ALL -j DROP

# ── FIN scan (FIN only, no ACK — stealth probe) ──────────────────────────
iptables -A HARDEN_INPUT -p tcp --tcp-flags ACK,FIN FIN \
  -j LOG --log-prefix "FW-FINSCAN: " --log-level 4
iptables -A HARDEN_INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP

# ── SYN/RST illegal combination ──────────────────────────────────────────
iptables -A HARDEN_INPUT -p tcp --tcp-flags SYN,RST SYN,RST \
  -j LOG --log-prefix "FW-SYNRST: " --log-level 4
iptables -A HARDEN_INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# ── Fragmented packets (often used in DoS / evasion) ─────────────────────
iptables -A HARDEN_INPUT -f \
  -j LOG --log-prefix "FW-FRAGMENT: " --log-level 4
iptables -A HARDEN_INPUT -f -j DROP

# ── SYN flood — per-source rate limit ────────────────────────────────────
# Allow 30 SYNs/s per IP, burst up to 60; excess is logged and dropped
iptables -A HARDEN_INPUT -p tcp --syn \
  -m hashlimit \
  --hashlimit-above 30/second --hashlimit-burst 60 \
  --hashlimit-mode srcip --hashlimit-name syn_flood \
  -j LOG --log-prefix "FW-SYNFLOOD: " --log-level 4
iptables -A HARDEN_INPUT -p tcp --syn \
  -m hashlimit \
  --hashlimit-above 30/second --hashlimit-burst 60 \
  --hashlimit-mode srcip --hashlimit-name syn_flood \
  -j DROP

# ── ICMP flood — per-source rate limit ───────────────────────────────────
iptables -A HARDEN_INPUT -p icmp --icmp-type echo-request \
  -m hashlimit \
  --hashlimit-above 5/second --hashlimit-burst 15 \
  --hashlimit-mode srcip --hashlimit-name icmp_flood \
  -j LOG --log-prefix "FW-ICMPFLOOD: " --log-level 4
iptables -A HARDEN_INPUT -p icmp --icmp-type echo-request \
  -m hashlimit \
  --hashlimit-above 5/second --hashlimit-burst 15 \
  --hashlimit-mode srcip --hashlimit-name icmp_flood \
  -j DROP

# ── UDP flood — per-source rate limit ────────────────────────────────────
iptables -A HARDEN_INPUT -p udp \
  -m hashlimit \
  --hashlimit-above 50/second --hashlimit-burst 100 \
  --hashlimit-mode srcip --hashlimit-name udp_flood \
  -j LOG --log-prefix "FW-UDPFLOOD: " --log-level 4
iptables -A HARDEN_INPUT -p udp \
  -m hashlimit \
  --hashlimit-above 50/second --hashlimit-burst 100 \
  --hashlimit-mode srcip --hashlimit-name udp_flood \
  -j DROP

# ── New connection rate — per-source ─────────────────────────────────────
iptables -A HARDEN_INPUT -p tcp -m conntrack --ctstate NEW \
  -m hashlimit \
  --hashlimit-above 15/second --hashlimit-burst 40 \
  --hashlimit-mode srcip --hashlimit-name conn_rate \
  -j LOG --log-prefix "FW-CONNRATE: " --log-level 4
iptables -A HARDEN_INPUT -p tcp -m conntrack --ctstate NEW \
  -m hashlimit \
  --hashlimit-above 15/second --hashlimit-burst 40 \
  --hashlimit-mode srcip --hashlimit-name conn_rate \
  -j DROP

# ── Concurrent connection limit — per-source ─────────────────────────────
iptables -A HARDEN_INPUT -p tcp -m conntrack --ctstate NEW \
  -m connlimit --connlimit-above 60 --connlimit-mask 32 \
  -j LOG --log-prefix "FW-CONNLIMIT: " --log-level 4
iptables -A HARDEN_INPUT -p tcp -m conntrack --ctstate NEW \
  -m connlimit --connlimit-above 60 --connlimit-mask 32 \
  -j DROP

# ── Bogon / spoofed source addresses arriving on WAN ────────────────────
# RFC 1918 private ranges, loopback, link-local, multicast, reserved
for bogon in \
    "10.0.0.0/8" \
    "172.16.0.0/12" \
    "192.168.0.0/16" \
    "127.0.0.0/8" \
    "169.254.0.0/16" \
    "224.0.0.0/4" \
    "240.0.0.0/4" \
    "0.0.0.0/8" \
    "100.64.0.0/10"; do
  iptables -A HARDEN_INPUT -i "${WAN_IFACE}" -s "${bogon}" \
    -j LOG --log-prefix "FW-BOGON: " --log-level 4
  iptables -A HARDEN_INPUT -i "${WAN_IFACE}" -s "${bogon}" -j DROP
done

# ── INSERT the hardening chain at the top of INPUT ───────────────────────
# Remove any stale jump first so we don't duplicate it on re-runs
iptables -D INPUT -j HARDEN_INPUT 2>/dev/null || true
iptables -I INPUT 1 -j HARDEN_INPUT

success "HARDEN_INPUT chain installed"

# ═══════════════════════════════════════════════════════════════════════════
step "4. iptables — HARDEN_FORWARD chain (anti-spoofing on forwarded traffic)"

iptables -N HARDEN_FORWARD 2>/dev/null || iptables -F HARDEN_FORWARD

# Block private-source packets arriving on WAN side (spoofed LAN source)
for bogon in \
    "10.0.0.0/8" \
    "172.16.0.0/12" \
    "192.168.0.0/16" \
    "127.0.0.0/8" \
    "169.254.0.0/16"; do
  iptables -A HARDEN_FORWARD -i "${WAN_IFACE}" -s "${bogon}" \
    -j LOG --log-prefix "FW-FWDSPOOFED: " --log-level 4
  iptables -A HARDEN_FORWARD -i "${WAN_IFACE}" -s "${bogon}" -j DROP
done

# Rate-limit new forwarded connections (DDoS amplification protection)
iptables -A HARDEN_FORWARD -p tcp -m conntrack --ctstate NEW \
  -m hashlimit \
  --hashlimit-above 100/second --hashlimit-burst 200 \
  --hashlimit-mode srcip --hashlimit-name fwd_rate \
  -j LOG --log-prefix "FW-FWDRATE: " --log-level 4
iptables -A HARDEN_FORWARD -p tcp -m conntrack --ctstate NEW \
  -m hashlimit \
  --hashlimit-above 100/second --hashlimit-burst 200 \
  --hashlimit-mode srcip --hashlimit-name fwd_rate \
  -j DROP

iptables -D FORWARD -j HARDEN_FORWARD 2>/dev/null || true
iptables -I FORWARD 1 -j HARDEN_FORWARD

success "HARDEN_FORWARD chain installed"

# ═══════════════════════════════════════════════════════════════════════════
step "5. iptables — SSH access hardening"

# Remove any pre-existing broad SSH ACCEPT rule so we can replace it
iptables -D INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT 2>/dev/null || true

if [[ -n "${SSH_FROM}" ]]; then
  # Restrict SSH to a specific source network — log & drop everything else
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -s "${SSH_FROM}" -j ACCEPT
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" \
    -j LOG --log-prefix "FW-SSH-DENY: " --log-level 4
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j DROP
  info "SSH locked to ${SSH_FROM}"
else
  # Rate-limit SSH new connections globally (brute-force protection)
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -m conntrack --ctstate NEW \
    -m hashlimit \
    --hashlimit-above 3/minute --hashlimit-burst 5 \
    --hashlimit-mode srcip --hashlimit-name ssh_ratelimit \
    -j LOG --log-prefix "FW-SSH-FLOOD: " --log-level 4
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -m conntrack --ctstate NEW \
    -m hashlimit \
    --hashlimit-above 3/minute --hashlimit-burst 5 \
    --hashlimit-mode srcip --hashlimit-name ssh_ratelimit \
    -j DROP
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT
  info "SSH rate-limited to 3 new connections/min per IP"
fi

success "SSH iptables rules applied"

# ═══════════════════════════════════════════════════════════════════════════
step "6. iptables — set default INPUT/FORWARD policy to DROP"

# Ensure loopback is accepted before we set DROP
iptables -D INPUT -i lo -j ACCEPT 2>/dev/null || true
iptables -I INPUT 2 -i lo -j ACCEPT

# Ensure ESTABLISHED/RELATED accepted before DROP kicks in
iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Log everything else that hits the bottom of INPUT
iptables -A INPUT -j LOG --log-prefix "FW-INPUT-DROP: " --log-level 4
iptables -A INPUT -j DROP

iptables -P INPUT   DROP
iptables -P FORWARD DROP

success "Default INPUT/FORWARD policy set to DROP"

# ═══════════════════════════════════════════════════════════════════════════
step "7. SSH daemon hardening"

SSHD_CONF="/etc/ssh/sshd_config"
cp -n "${SSHD_CONF}" "${SSHD_CONF}.bak.$(date +%Y%m%d%H%M%S)" \
  && info "sshd_config backed up"

# Helper: set or replace an sshd_config directive (handles commented lines)
sshd_set() {
  local key="$1" value="$2"
  if grep -qE "^#?${key}\b" "${SSHD_CONF}"; then
    sed -i "s|^#*\s*${key}\b.*|${key} ${value}|" "${SSHD_CONF}"
  else
    echo "${key} ${value}" >> "${SSHD_CONF}"
  fi
}

sshd_set Protocol           2
sshd_set PermitRootLogin    no
sshd_set PasswordAuthentication no
sshd_set PermitEmptyPasswords  no
sshd_set ChallengeResponseAuthentication no
sshd_set UsePAM             yes
sshd_set X11Forwarding      no
sshd_set MaxAuthTries        3
sshd_set LoginGraceTime      20
sshd_set MaxSessions         5
sshd_set MaxStartups        "5:50:15"
sshd_set ClientAliveInterval 300
sshd_set ClientAliveCountMax 2
sshd_set LogLevel            VERBOSE
sshd_set StrictModes         yes
sshd_set IgnoreRhosts        yes
sshd_set HostbasedAuthentication no

# Only allow public-key authentication
sshd_set PubkeyAuthentication yes

# Validate config before reloading
if sshd -t; then
  systemctl reload sshd || systemctl restart ssh
  success "SSH daemon hardened and reloaded"
else
  error "sshd_config validation failed — restoring backup"
  cp "${SSHD_CONF}.bak."* "${SSHD_CONF}" 2>/dev/null || true
fi

# ═══════════════════════════════════════════════════════════════════════════
step "8. fail2ban (SSH brute-force + iptables-log jails)"

FAIL2BAN_LOCAL="/etc/fail2ban/jail.local"
cat > "${FAIL2BAN_LOCAL}" <<EOF
[DEFAULT]
bantime  = 3600
findtime = 300
maxretry = 3
banaction = iptables-multiport
logpath  = /var/log/auth.log
# Never ban the LAN gateway itself
ignoreip = 127.0.0.1/8 10.42.0.0/24

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200
findtime = 120

# ── Custom jail: iptables-logged port scans ──────────────────────────────
# Reads kernel log lines like: FW-NULLSCAN: IN=eth0 SRC=1.2.3.4 ...
[pi-portscan]
enabled  = true
filter   = pi-portscan
logpath  = /var/log/kern.log
maxretry = 2
bantime  = 86400
findtime = 60

# ── Custom jail: iptables-logged bogon sources ───────────────────────────
[pi-bogon]
enabled  = true
filter   = pi-bogon
logpath  = /var/log/kern.log
maxretry = 3
bantime  = 86400
findtime = 60

# ── Custom jail: repeated FW-INPUT-DROP from same IP ────────────────────
[pi-inputdrop]
enabled  = true
filter   = pi-inputdrop
logpath  = /var/log/kern.log
maxretry = 10
bantime  = 3600
findtime = 60
EOF

# fail2ban filter for port scans
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/pi-portscan.conf <<'EOF'
[Definition]
failregex = .*FW-NULLSCAN:.*SRC=<HOST>
            .*FW-XMASSCAN:.*SRC=<HOST>
            .*FW-FINSCAN:.*SRC=<HOST>
            .*FW-SYNRST:.*SRC=<HOST>
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/pi-bogon.conf <<'EOF'
[Definition]
failregex = .*FW-BOGON:.*SRC=<HOST>
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/pi-inputdrop.conf <<'EOF'
[Definition]
failregex = .*FW-INPUT-DROP:.*SRC=<HOST>
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
success "fail2ban configured and started"

# ═══════════════════════════════════════════════════════════════════════════
step "9. arpwatch (ARP spoofing / MITM detection)"

# arpwatch monitors the ARP table and emails / logs any MAC changes.
# On Raspberry Pi OS, logs go to syslog. We redirect alerts to our log too.
ARPWATCH_CONF="/etc/arpwatch.conf"

# Configure arpwatch to log to syslog (no email needed — watchdog reads syslog)
if [[ -f /etc/default/arpwatch ]]; then
  sed -i 's|^ARGS=.*|ARGS="-N -p -i '"${WAN_IFACE}"'"|' /etc/default/arpwatch
fi

# Create a secondary arpwatch instance for the LAN interface
cat > /etc/systemd/system/arpwatch-lan.service <<EOF
[Unit]
Description=arpwatch — ARP spoofing monitor on ${LAN_IFACE}
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/arpwatch -N -p -i ${LAN_IFACE} -f /var/lib/arpwatch/${LAN_IFACE}.dat
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /var/lib/arpwatch
touch /var/lib/arpwatch/${LAN_IFACE}.dat

systemctl daemon-reload
systemctl enable  arpwatch 2>/dev/null || true
systemctl restart arpwatch 2>/dev/null || true
systemctl enable  arpwatch-lan
systemctl restart arpwatch-lan
success "arpwatch running on ${WAN_IFACE} and ${LAN_IFACE}"

# ═══════════════════════════════════════════════════════════════════════════
step "10. Deploy watchdog daemon (pi_watchdog.py)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/pi_watchdog.py" ]]; then
  cp "${SCRIPT_DIR}/pi_watchdog.py" "${BLOCKER_DIR}/pi_watchdog.py"
  chown root:root "${BLOCKER_DIR}/pi_watchdog.py"
  chmod 750 "${BLOCKER_DIR}/pi_watchdog.py"
  info "pi_watchdog.py copied to ${BLOCKER_DIR}"
else
  warn "pi_watchdog.py not found next to this script — skipping copy"
fi

AUTOBLOCK_FLAG="true"
[[ "${AUTOBLOCK}" == "false" ]] && AUTOBLOCK_FLAG="false"

# ── Enable BCM2835/BCM2711 built-in hardware watchdog ─────────────────────
info "Enabling Raspberry Pi hardware watchdog (bcm2835_wdt)..."

# 1. Device-tree overlay — tells the firmware to expose /dev/watchdog
for cfg in /boot/firmware/config.txt /boot/config.txt; do
  if [[ -f "${cfg}" ]]; then
    grep -q "dtparam=watchdog=on" "${cfg}" \
      || echo "dtparam=watchdog=on" >> "${cfg}"
    info "  dtparam=watchdog=on written to ${cfg}"
    break
  fi
done

# 2. Load the kernel module now (also persists across reboots via /etc/modules)
modprobe bcm2835_wdt 2>/dev/null || warn "  modprobe bcm2835_wdt failed — may need a reboot first"
grep -q "^bcm2835_wdt" /etc/modules || echo "bcm2835_wdt" >> /etc/modules

# 3. Tell systemd to keep the hardware WDT alive itself (belt-and-suspenders).
#    RuntimeWatchdogSec — systemd pets /dev/watchdog every 15 s.
#    RebootWatchdogSec  — if a reboot hangs >10 min, hardware forces it.
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/99-hardware-watchdog.conf <<'HEREDOC'
[Manager]
RuntimeWatchdogSec=15
RebootWatchdogSec=10min
HEREDOC
systemctl daemon-reexec 2>/dev/null || true
success "Hardware watchdog enabled"

cat > /etc/systemd/system/pi-watchdog.service <<EOF
[Unit]
Description=Pi Security Watchdog — MITM/ARP/DDoS/Scan/Brute monitor
After=network.target chromecast-blocker.service
Wants=network.target

[Service]
# Type=notify lets systemd track READY=1 / WATCHDOG=1 / STOPPING=1 signals
Type=notify
NotifyAccess=main
# If the watchdog daemon stops sending WATCHDOG=1 within 30 s, systemd
# kills and restarts it (separate from the hardware /dev/watchdog timeout)
WatchdogSec=30
User=root
WorkingDirectory=${BLOCKER_DIR}
ExecStart=${BLOCKER_DIR}/venv/bin/python3 ${BLOCKER_DIR}/pi_watchdog.py \
    --wan-iface ${WAN_IFACE} \
    --lan-iface ${LAN_IFACE} \
    --log-dir   ${LOG_DIR} \
    --autoblock ${AUTOBLOCK_FLAG} \
    --block-expire 86400
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/watchdog.log
StandardError=append:${LOG_DIR}/watchdog.log
# Give it elevated privilege only for iptables/arptables
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# Install psutil into the blocker venv (needed by watchdog)
"${BLOCKER_DIR}/venv/bin/pip" install -q --upgrade psutil 2>/dev/null || \
  warn "Could not install psutil into venv — watchdog process stats unavailable"

systemctl daemon-reload
systemctl enable pi-watchdog.service
systemctl start  pi-watchdog.service
success "Watchdog service installed and started"

# ═══════════════════════════════════════════════════════════════════════════
step "11. Deploy intrusion trace utility and configure log rotation"

# Install trace_intruder.py alongside the watchdog
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/trace_intruder.py" ]]; then
    cp "${SCRIPT_DIR}/trace_intruder.py" "${INSTALL_DIR}/trace_intruder.py"
    chmod +x "${INSTALL_DIR}/trace_intruder.py"
    # Convenience symlink so it's on PATH for any user running as root
    ln -sf "${INSTALL_DIR}/trace_intruder.py" /usr/local/sbin/trace_intruder
    success "trace_intruder installed → /usr/local/sbin/trace_intruder"
else
    warn "trace_intruder.py not found next to harden_pi.sh — skipping"
fi

# Logrotate config for watchdog logs
cat > /etc/logrotate.d/pi-watchdog <<'EOF'
/opt/chromecast_blocker/logs/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl kill -s HUP pi-watchdog.service 2>/dev/null || true
    endscript
}
EOF
chmod 644 /etc/logrotate.d/pi-watchdog
success "Logrotate configured (weekly, 12 weeks, gzip)"

# ═══════════════════════════════════════════════════════════════════════════
step "12. Save iptables rules (persistent across reboots)"

netfilter-persistent save
success "iptables rules saved"

# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║          Hardening Complete                                ║${NC}"
echo -e "${GREEN}${BOLD}╠════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Kernel:   anti-MITM · rp_filter · SYN cookies · ASLR     ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Firewall: scan drops · DDoS hashlimit · bogon filter      ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  SSH:      public-key only · MaxAuthTries 3 · rate limit   ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  fail2ban: SSH jail · port-scan jail · bogon jail          ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  arpwatch: ARP spoof detection on WAN + LAN                ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Watchdog: auto-block · ARP · flood · scan · brute-force   ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Trace:    trace_intruder  (IP timeline + attack details)  ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Logs:                                                     ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    ${LOG_DIR}/watchdog.log  (full events)  ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    ${LOG_DIR}/intrusions.log  (WARNING+) ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    /var/log/kern.log   (FW-* iptables entries)             ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    /var/log/auth.log   (SSH attempts)                      ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    journalctl -u arpwatch                                  ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    journalctl -u pi-watchdog                               ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Intrusion tracing:                                        ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    sudo trace_intruder                  # all intruders    ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    sudo trace_intruder --ip 1.2.3.4     # one IP timeline  ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    sudo trace_intruder --since 24h      # last 24 h        ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Service control:                                          ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    systemctl status pi-watchdog                            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    fail2ban-client status                                  ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}    fail2ban-client status pi-portscan                      ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}                                                            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  IMPORTANT: SSH now requires a public key.                 ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  Ensure your key is in ~/.ssh/authorized_keys before       ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}║${NC}  closing your current SSH session!                         ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
warn "Reboot recommended to apply all kernel parameters: sudo reboot"
