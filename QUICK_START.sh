#!/bin/bash
# Quick Reference Guide for Chromecast Blocker

echo "=== Chromecast Blocker Quick Reference ==="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  Some commands require root access. Use 'sudo' if needed."
   echo ""
fi

echo "📍 STEP 1: Install Dependencies"
echo "   sudo bash install.sh"
echo ""

echo "🔍 STEP 2: Discover Chromecast on Your Network"
echo "   sudo python3 chromecast_blocker.py discover"
echo "   Example output: Found Chromecast devices: 10.42.0.1"
echo ""

echo "🛡️  STEP 3: Apply Full Protection"
echo "   sudo python3 chromecast_blocker.py full-protect --ip 10.42.0.1"
echo "   This blocks: external access, eavesdropping, DDoS, MITM, and isolates device"
echo ""

echo "✅ STEP 4: Verify Protection is Active"
echo "   sudo python3 chromecast_blocker.py status --ip 10.42.0.1"
echo "   Shows: active rules, protections enabled, isolation status"
echo ""

echo "📊 ADDITIONAL COMMANDS"
echo ""

echo "Monitor Traffic (Real-time)"
echo "   sudo python3 chromecast_blocker.py monitor --ip 10.42.0.1 --duration 600"
echo ""

echo "Use Config File (for multiple devices)"
echo "   1. Edit config.yaml with your device IPs"
echo "   2. sudo python3 advanced_blocker.py --config config.yaml protect-all"
echo ""

echo "Continuous Monitoring"
echo "   sudo python3 advanced_blocker.py --config config.yaml monitor"
echo "   Monitors all devices continuously for suspicious activity"
echo ""

echo "View Protection Summary"
echo "   sudo python3 advanced_blocker.py --config config.yaml summary"
echo ""

echo "Backup Firewall Rules"
echo "   sudo python3 advanced_blocker.py --config config.yaml export --output rules-backup.txt"
echo ""

echo "Install as Systemd Service (auto-start on boot)"
echo "   sudo bash install.sh  # Choose 'y' for systemd installation"
echo "   sudo systemctl start chromecast-blocker"
echo "   sudo systemctl status chromecast-blocker"
echo ""

echo "Remove All Protection Rules"
echo "   sudo python3 chromecast_blocker.py flush"
echo "   ⚠️  This removes ALL firewall rules - use with caution!"
echo ""

echo "🔧 TROUBLESHOOTING"
echo ""

echo "View Firewall Rules"
echo "   sudo iptables -L -n"
echo ""

echo "Monitor Live Network Traffic"
echo "   sudo tcpdump -i eth0 host 10.42.0.1"
echo ""

echo "View Logs"
echo "   tail -f chromecast_blocker.log"
echo ""

echo "Check if Chromecast is Responsive"
echo "   ping 10.42.0.1 (should respond from local network)"
echo "   curl http://10.42.0.1:8008 (should work on local network)"
echo ""

echo "Restore Firewall from Backup"
echo "   sudo python3 advanced_blocker.py --config config.yaml import --input rules-backup.txt"
echo ""

echo "📝 WHAT EACH PROTECTION DOES"
echo ""

echo "1. Block External Access"
echo "   - Prevents WAN/internet access to Chromecast"
echo "   - Only allows local network (192.168.x.x, 10.x.x.x, 172.16-31.x.x)"
echo ""

echo "2. Block Eavesdropping"
echo "   - Blocks all Google cloud connectivity"
echo "   - Prevents data transmission to analytics/telemetry"
echo "   - Rate-limits HTTPS/HTTP connections"
echo ""

echo "3. Block DDoS Amplification"
echo "   - Stops device from being used in large-scale attacks"
echo "   - Blocks mDNS, SSDP, DNS, NTP amplification vectors"
echo "   - Rate-limits potentially dangerous protocols"
echo ""

echo "4. Block MITM Attacks"
echo "   - Prevents ARP spoofing"
echo "   - Drops malformed/invalid packets"
echo "   - Validates packet states"
echo ""

echo "5. Network Isolation"
echo "   - Forces Chromecast to local network ONLY"
echo "   - Blocks outbound connections to WAN"
echo "   - Prevents lateral movement to other systems"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo ""
echo "For detailed documentation, see README.md"
