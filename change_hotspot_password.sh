#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  change_hotspot_password.sh — Change the hotspot password live          ║
# ║                                                                          ║
# ║  Usage:  sudo bash change_hotspot_password.sh <new_password>            ║
# ║                                                                          ║
# ║  The change takes effect immediately without a full reboot.             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run this script with sudo"

# ── Read current config ───────────────────────────────────────────────────
CONF="/etc/chromecast_blocker/hotspot.conf"
[[ -f "$CONF" ]] || error "Hotspot config not found at ${CONF}. Run setup_hotspot.sh first."
# shellcheck source=/dev/null
source "$CONF"

# ── Get new password ──────────────────────────────────────────────────────
NEW_PASS="${1:-}"

if [[ -z "$NEW_PASS" ]]; then
  echo ""
  read -rsp "  Enter new hotspot password (8–63 chars): " NEW_PASS
  echo ""
fi

PASS_LEN="${#NEW_PASS}"
if (( PASS_LEN < 8 || PASS_LEN > 63 )); then
  error "Passphrase must be 8–63 characters (got ${PASS_LEN})"
fi

echo ""
echo -e "  SSID        : ${CYAN}${SSID}${NC}"
echo -e "  New password: ${CYAN}${NEW_PASS}${NC}"
echo ""
read -rp "Apply? [y/N] " ans
[[ "${ans,,}" == "y" ]] || { info "Aborted."; exit 0; }

# ── Apply change ──────────────────────────────────────────────────────────
if [[ "${USE_NM}" == "true" ]]; then
  # ── NetworkManager ──────────────────────────────────────────────────────
  info "Updating NetworkManager connection '${NM_CON}'..."
  nmcli con modify "${NM_CON}" wifi-sec.psk "${NEW_PASS}"
  nmcli con down "${NM_CON}" 2>/dev/null || true
  sleep 1
  nmcli con up   "${NM_CON}"
  success "Hotspot password updated and connection restarted"

else
  # ── Legacy hostapd ──────────────────────────────────────────────────────
  HOSTAPD_CONF="/etc/hostapd/hostapd.conf"
  [[ -f "$HOSTAPD_CONF" ]] || error "hostapd config not found at ${HOSTAPD_CONF}"

  info "Updating ${HOSTAPD_CONF}..."
  sed -i "s|^wpa_passphrase=.*|wpa_passphrase=${NEW_PASS}|" "${HOSTAPD_CONF}"

  info "Restarting hostapd..."
  systemctl restart hostapd
  success "hostapd restarted with new password"
fi

# ── Update saved config ───────────────────────────────────────────────────
sed -i "s|^PASSPHRASE=.*|PASSPHRASE=\"${NEW_PASS}\"|" "${CONF}"
success "Saved config updated"

echo ""
echo -e "${BOLD}  Password changed successfully.${NC}"
echo -e "  Connect to ${BOLD}${SSID}${NC} with the new password: ${BOLD}${NEW_PASS}${NC}"
echo ""
