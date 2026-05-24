#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   Chromecast Security Blocker — Pi Startup Sequence          ║
# ║   Opens automatically at desktop login via autostart         ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Flow:
#   1. Wait for wlan0 hotspot to be up
#   2. Discover Chromecast devices (10.42.0.0/24)
#   3. Apply full protection (advanced_blocker.py protect-all)
#   4. Show protection summary
#   5. Launch live status dashboard

WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$WORK_DIR/venv/bin/python3"
CONFIG="$WORK_DIR/config.yaml"
HOTSPOT_GW="10.42.0.1"
SCAN_RANGE="10.42.0.0/24"

# Pick python: prefer venv, fall back to system
[[ -x "$VENV_PYTHON" ]] && PYTHON="$VENV_PYTHON" || PYTHON="python3"

# ── Helpers ──────────────────────────────────────────────────────
banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   $1$(printf '%*s' $((59 - ${#1})) '')║"
    echo "╚══════════════════════════════════════════════════════════════╝"
}
step()    { echo ""; echo "▶  $*"; echo ""; }
ok()      { echo "   ✓  $*"; }
fail()    { echo "   ✗  $*"; }
divider() { echo "   ──────────────────────────────────────────────────────"; }

# ── Step 1: Wait for hotspot interface ───────────────────────────
clear
banner "CHROMECAST SECURITY BLOCKER — STARTUP"

step "Ensuring wlan0 hotspot is active ($HOTSPOT_GW)..."

# Actively bring up the hotspot if not already running
if ! ip addr show wlan0 2>/dev/null | grep -q "10\.42\.0\."; then
    ok "Hotspot not yet up — starting chromecast-hotspot via NetworkManager..."
    sudo nmcli con up chromecast-hotspot 2>/dev/null \
        && ok "nmcli: chromecast-hotspot activated" \
        || fail "nmcli: could not start hotspot (will keep waiting)"
fi

MAX_WAIT=60
WAITED=0
while ! ip addr show wlan0 2>/dev/null | grep -q "10\.42\.0\."; do
    if [[ $WAITED -ge $MAX_WAIT ]]; then
        fail "wlan0 hotspot did not come up after ${MAX_WAIT}s — continuing anyway"
        break
    fi
    printf "   ... %ds / %ds\r" "$WAITED" "$MAX_WAIT"
    sleep 2
    WAITED=$((WAITED + 2))
done
ok "wlan0 hotspot is up"

# Short extra pause so DHCP can assign addresses to clients
sleep 3

# ── Step 2: Discover Chromecast ───────────────────────────────────
step "Scanning $SCAN_RANGE for Chromecast devices..."
divider

cd "$WORK_DIR" || exit 1
DISCOVERED=$(sudo "$PYTHON" "$WORK_DIR/chromecast_blocker.py" discover \
    --scan-range "$SCAN_RANGE" \
    --scan-timeout 45 2>/dev/null)

CC_IP_DISCOVERED=""
if echo "$DISCOVERED" | grep -q "Found Chromecast"; then
    ok "$DISCOVERED"
    FOUND=true
    # Extract the first discovered IP address
    CC_IP_DISCOVERED=$(echo "$DISCOVERED" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    if [[ -n "$CC_IP_DISCOVERED" ]]; then
        ok "Discovered Chromecast IP: $CC_IP_DISCOVERED"
        # Update config.yaml so monitor/summary tools also use the live IP
        "$PYTHON" -c "
import yaml, sys
with open('$CONFIG') as f:
    c = yaml.safe_load(f) or {}
devs = c.setdefault('chromecast_devices', [])
if devs:
    devs[0]['ip'] = '$CC_IP_DISCOVERED'
else:
    devs.append({'name': 'Chromecast', 'ip': '$CC_IP_DISCOVERED', 'enabled': True})
with open('$CONFIG', 'w') as f:
    yaml.dump(c, f, default_flow_style=False)
" 2>/dev/null && ok "config.yaml updated with discovered IP" \
                  || fail "Could not update config.yaml (using existing)"
    fi
else
    fail "No Chromecast found on $SCAN_RANGE (will still apply configured protection)"
    FOUND=false
fi
divider

# ── Step 3: Apply full protection ────────────────────────────────
if [[ -n "$CC_IP_DISCOVERED" ]]; then
    step "Applying full protection to discovered Chromecast ($CC_IP_DISCOVERED)..."
    divider
    sudo "$PYTHON" "$WORK_DIR/chromecast_blocker.py" full-protect --ip "$CC_IP_DISCOVERED"
else
    step "Applying full protection from config.yaml..."
    divider
    sudo "$PYTHON" "$WORK_DIR/advanced_blocker.py" --config "$CONFIG" protect-all
fi
divider

# ── Step 4: Show protection summary ──────────────────────────────
step "Protection summary:"
divider
sudo "$PYTHON" "$WORK_DIR/advanced_blocker.py" --config "$CONFIG" summary
divider

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   STARTUP COMPLETE — Protection is ACTIVE                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "   Launching live status dashboard in 5 seconds..."
echo "   (Press Ctrl+C to stay at this summary)"
echo ""

sleep 5

# ── Step 5: Live dashboard ────────────────────────────────────────
# Use the discovered IP if available; otherwise fall back to config.yaml
if [[ -z "$CC_IP_DISCOVERED" ]]; then
    CC_IP_DISCOVERED=$("$PYTHON" -c "import yaml; c=yaml.safe_load(open('$CONFIG')); print(c['chromecast_devices'][0]['ip'])" 2>/dev/null || echo "10.42.0.88")
fi

exec sudo "$PYTHON" "$WORK_DIR/status_monitor.py" "$CC_IP_DISCOVERED"
