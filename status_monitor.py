#!/usr/bin/env python3
"""
Status Monitor - Real-time dashboard for Chromecast protection status
"""

import subprocess
import time
import os
import sys
from datetime import datetime
from chromecast_blocker import ChromecastBlocker


class StatusMonitor:
    """Real-time status monitoring dashboard"""
    
    def __init__(self, chromecast_ips: list = None):
        """Initialize monitor with list of IPs to track"""
        self.chromecast_ips = chromecast_ips or []
        self.blocker = ChromecastBlocker()
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def get_active_iptable_rules(self) -> int:
        """Get count of active iptables rules"""
        try:
            result = subprocess.run(
                'iptables -L -n | wc -l',
                shell=True,
                capture_output=True,
                text=True
            )
            return int(result.stdout.strip())
        except:
            return 0
    
    def get_net_traffic(self, ip: str) -> dict:
        """Get traffic statistics for an IP"""
        try:
            # Use netstat to get connection info
            result = subprocess.run(
                f'netstat -an | grep {ip} | wc -l',
                shell=True,
                capture_output=True,
                text=True
            )
            return {'connections': int(result.stdout.strip())}
        except:
            return {'connections': 0}
    
    def display_dashboard(self):
        """Display real-time status dashboard"""
        try:
            while True:
                self.clear_screen()
                
                print("╔════════════════════════════════════════════════════════════╗")
                print("║     CHROMECAST SECURITY BLOCKER - STATUS DASHBOARD         ║")
                print("╚════════════════════════════════════════════════════════════╝")
                print("")
                print(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Active Firewall Rules: {self.get_active_iptable_rules()}")
                print("")
                
                for ip in self.chromecast_ips:
                    status = self.blocker.get_status(ip)
                    protections = status['protections']
                    traffic = self.get_net_traffic(ip)
                    
                    print(f"Device: {ip}")
                    print(f"{'─' * 60}")
                    print(f"  External Access Blocked:        {'✓ YES' if protections['external_access_blocked'] else '✗ NO':>35}")
                    print(f"  Eavesdropping Blocked:          {'✓ YES' if protections['eavesdropping_blocked'] else '✗ NO':>35}")
                    print(f"  DDoS Amplification Blocked:     {'✓ YES' if protections['ddos_amplification_blocked'] else '✗ NO':>35}")
                    print(f"  MITM Protection Active:         {'✓ YES' if protections['mitm_protected'] else '✗ NO':>35}")
                    print(f"  Network Isolated (Local Only):  {'✓ YES' if protections['isolated'] else '✗ NO':>35}")
                    print(f"  Active Connections:             {traffic['connections']:>35}")
                    print("")
                
                # Overall status
                all_protected = all(
                    self.blocker.get_status(ip)['protections'].get(key)
                    for ip in self.chromecast_ips
                    for key in self.blocker.get_status(ip)['protections'].keys()
                )
                
                if all_protected and self.chromecast_ips:
                    print("╔════════════════════════════════════════════════════════════╗")
                    print("║  STATUS: 🛡️  FULLY PROTECTED - All devices secured        ║")
                    print("╚════════════════════════════════════════════════════════════╝")
                else:
                    print("╔════════════════════════════════════════════════════════════╗")
                    print("║  STATUS: ⚠️  PARTIAL PROTECTION - Review above status      ║")
                    print("╚════════════════════════════════════════════════════════════╝")
                
                print("")
                print("Press Ctrl+C to exit | Refreshing in 30 seconds...")
                
                time.sleep(30)
        
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")
            sys.exit(0)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Chromecast Blocker Status Monitor')
    parser.add_argument('ips', nargs='*', help='Chromecast IP addresses to monitor')
    
    args = parser.parse_args()
    
    if not args.ips:
        print("Usage: python3 status_monitor.py <IP1> <IP2> ...")
        print("Example: python3 status_monitor.py 10.42.0.1 10.42.0.2")
        sys.exit(1)
    
    monitor = StatusMonitor(chromecast_ips=args.ips)
    monitor.display_dashboard()


if __name__ == '__main__':
    main()
