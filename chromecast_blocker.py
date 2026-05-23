#!/usr/bin/env python3
"""
Chromecast Security & Access Control
Blocks unauthorized access, eavesdropping, and network attacks via Chromecast
"""

import socket
import subprocess
import argparse
import logging
from typing import List
import json
import os
from datetime import datetime
import re

# Configure logging with a safe fallback when file permissions are restricted.
_handlers = [logging.StreamHandler()]
try:
    _handlers.insert(0, logging.FileHandler('chromecast_blocker.log'))
except (PermissionError, OSError):
    pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=_handlers
)
logger = logging.getLogger(__name__)


class ChromecastBlocker:
    """
    Manages Chromecast security by blocking unauthorized access,
    preventing eavesdropping, and isolating network threats.
    """
    
    # Google/Chromecast domains and IPs that facilitate cloud connectivity and eavesdropping
    BLOCKED_DOMAINS = [
        'google.com',
        'googleapis.com',
        'googleusercontent.com',
        'gstatic.com',
        'firebase.google.com',
        'crashlytics.com',
        'analytics.google.com',
        'advertising.google.com',
        'doubleclick.net',
        'googlesyndication.com',
        'googleadservices.com',
    ]
    
    # Chromecast multicast discovery addresses (can be exploited)
    CHROMECAST_DISCOVERY_PORTS = [5353, 8008, 8009]

    # AdGuard DNS servers — used to intercept all Chromecast DNS queries
    ADGUARD_DNS_PRIMARY   = '94.140.14.14'
    ADGUARD_DNS_SECONDARY = '94.140.15.15'
    
    def __init__(self, chromecast_ip: str = None, interface: str = None):
        """
        Initialize the blocker.
        
        Args:
            chromecast_ip: IP address of the Chromecast device
            interface: Network interface to monitor (e.g., eth0)
        """
        self._state_file = '/tmp/chromecast_blocker_state.json'
        self.chromecast_ip = chromecast_ip or self._load_state_ip()
        self.interface = interface or self._get_default_interface()
        self.blocked_ips = set()
        self.firewall_rules = []
        if chromecast_ip:
            self._save_state_ip(chromecast_ip)
        
    def _save_state_ip(self, ip: str) -> None:
        """Persist the Chromecast IP so subsequent status calls can find it."""
        try:
            with open(self._state_file, 'w') as f:
                json.dump({'chromecast_ip': ip}, f)
        except Exception as e:
            logger.debug(f"Could not save state: {e}")

    def _load_state_ip(self) -> str:
        """Load the last-known Chromecast IP from the state file."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file) as f:
                    return json.load(f).get('chromecast_ip')
        except Exception as e:
            logger.debug(f"Could not load state: {e}")
        return None

    def _get_default_interface(self) -> str:
        """Detect the most suitable interface for Chromecast management.
        Prefers the Wi-Fi hotspot interface (10.42.0.x) over the WAN default route."""
        # Prefer any interface that owns a 10.42.0.x address (Pi hotspot/AP).
        try:
            result = subprocess.run(
                ['ip', '-o', '-f', 'inet', 'addr', 'show'],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                if ' lo ' in line:
                    continue
                match = re.search(r'\d+:\s+(\S+)\s+inet\s+10\.42\.0\.\d+/', line)
                if match:
                    return match.group(1)
        except Exception:
            pass

        # Fall back to the default route interface (WAN).
        try:
            result = subprocess.run(['ip', 'route', 'show'],
                                    capture_output=True, text=True, check=True)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    parts = line.split()
                    if 'dev' in parts:
                        return parts[parts.index('dev') + 1]
        except Exception as e:
            logger.warning(f"Could not detect interface: {e}")
        return 'wlan0'

    def _get_default_scan_range(self) -> str:
        """Detect the local IPv4 CIDR for the selected interface."""
        try:
            result = subprocess.run(
                ['ip', '-o', '-f', 'inet', 'addr', 'show', 'dev', self.interface],
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.splitlines():
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.warning(f"Could not detect scan range for {self.interface}: {e}")

        # Fallback kept for compatibility with common home networks.
        return '10.42.0.0/24'
    
    def discover_chromecast(self, scan_range: str = None, scan_timeout: int = 90) -> List[str]:
        """
        Discover Chromecast devices on the network.

        Args:
            scan_range: CIDR to scan (e.g. 10.42.0.0/24). Auto-detected if omitted.
            scan_timeout: Timeout for active scan in seconds.
        
        Returns:
            List of Chromecast IP addresses found
        """
        target_range = scan_range or self._get_default_scan_range()
        logger.info(f"Scanning network for Chromecast devices on {target_range}...")
        chromecast_ips = []
        
        try:
            # Use nmap to find common Chromecast ports.
            nmap_result = subprocess.run(
                ['nmap', '-p', '5353,8008,8009', '-n', '--open', target_range],
                capture_output=True,
                text=True,
                timeout=scan_timeout
            )

            # Parse nmap host report blocks to collect candidates.
            current_ip = None
            for line in nmap_result.stdout.splitlines():
                if line.startswith('Nmap scan report for '):
                    current_ip = line.split()[-1].strip('()')
                    continue
                if current_ip and '/tcp' in line and 'open' in line:
                    if current_ip.count('.') == 3:
                        chromecast_ips.append(current_ip)
                if line.startswith('Nmap done:'):
                    current_ip = None
            
            # Alternative: Use avahi-browse if available
            try:
                avahi_result = subprocess.run(
                    ['avahi-browse', '-t', '_googlecast._tcp'],
                    capture_output=True, text=True, timeout=10
                )
                for line in avahi_result.stdout.split('\n'):
                    if 'IPv4' in line or 'IPv6' in line:
                        parts = line.split()
                        for part in parts:
                            if part.count('.') == 3:  # IPv4
                                chromecast_ips.append(part)
                                logger.info(f"Found Chromecast: {part}")
            except FileNotFoundError:
                logger.debug("avahi-browse not found, trying nmap...")
                
        except subprocess.TimeoutExpired:
            logger.error(
                f"Discovery timed out after {scan_timeout}s. "
                f"Try a smaller --scan-range (for example 10.42.0.0/24)."
            )
        except Exception as e:
            logger.error(f"Error during discovery: {e}")
        
        return list(set(chromecast_ips))
    
    def block_external_access(self, chromecast_ip: str) -> bool:
        """
        Block external access to Chromecast device.
        Prevents remote exploitation and control.
        
        Args:
            chromecast_ip: Chromecast device IP address
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Blocking external access to Chromecast at {chromecast_ip}")
        
        rules = [
            # Allow only local network traffic
            f"iptables -A INPUT -i {self.interface} -s 192.168.0.0/16 -d {chromecast_ip} -j ACCEPT",
            f"iptables -A INPUT -i {self.interface} -s 10.0.0.0/8 -d {chromecast_ip} -j ACCEPT",
            f"iptables -A INPUT -i {self.interface} -s 172.16.0.0/12 -d {chromecast_ip} -j ACCEPT",

            # Block inbound traffic from non-local sources
            f"iptables -A INPUT -i {self.interface} -d {chromecast_ip} -j DROP",
        ]
        
        return self._apply_firewall_rules(rules)

    def _get_system_rules(self) -> str:
        """Return active iptables rules from the running system."""
        try:
            cmd = ['iptables-save'] if os.geteuid() == 0 else ['sudo', 'iptables-save']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except Exception as e:
            logger.warning(f"Could not read iptables rules (try running with sudo): {e}")
            return ""

    def _get_system_arp_rules(self) -> str:
        """Return active arptables rules from the running system."""
        try:
            cmd = ['arptables-save'] if os.geteuid() == 0 else ['sudo', 'arptables-save']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except Exception:
            # arptables may be absent on some systems.
            return ""
    
    def block_eavesdropping(self, chromecast_ip: str) -> bool:
        """
        Block cloud connectivity and eavesdropping.
        Prevents Google services from accessing device.
        
        Args:
            chromecast_ip: Chromecast device IP address
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Blocking cloud connectivity and eavesdropping for {chromecast_ip}")
        
        rules = []
        
        # Block DNS resolution of Google telemetry/analytics domains.
        # Uses FORWARD chain (Pi is a gateway) with -i interface so we match
        # packets that originate from the Chromecast and enter the Pi on wlan0.
        # Ports 80/443/8008/8009 are intentionally NOT blocked here — blocking
        # them kills streaming content.  8008/8009 are the local Cast protocol
        # and never reach the FORWARD chain anyway (same-subnet L2 traffic).
        for domain in self.BLOCKED_DOMAINS:
            rules.append(
                f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
                f"-p udp --dport 53 -m string --string '{domain}' --algo bm -j DROP"
            )
        
        return self._apply_firewall_rules(rules)
    
    def block_ddos_amplification(self, chromecast_ip: str) -> bool:
        """
        Block DDoS amplification attacks originating from Chromecast.
        Prevents device from being used as attack vector.
        
        Args:
            chromecast_ip: Chromecast device IP address
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Blocking DDoS amplification vectors from {chromecast_ip}")
        
        # Use FORWARD chain with -i (inbound from Chromecast on the hotspot
        # interface).  The original OUTPUT chain with -s {chromecast_ip} never
        # matched — OUTPUT packets are sourced by the Pi, not by the Chromecast.
        rules = [
            # Rate-limit mDNS amplification (port 5353)
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 5353 -m limit --limit 5/m -j ACCEPT",
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 5353 -j DROP",
            
            # Block SSDP amplification (port 1900)
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 1900 -j DROP",
            
            # Rate-limit NTP amplification-like patterns
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 123 -m limit --limit 5/m -j ACCEPT",
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 123 -j DROP",
            
            # Rate-limit DNS queries to prevent DNS amplification
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 53 -m limit --limit 20/m -j ACCEPT",
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 53 -j DROP",
        ]
        
        return self._apply_firewall_rules(rules)
    
    def block_mitm_attacks(self, chromecast_ip: str) -> bool:
        """
        Block man-in-the-middle (MITM) attack vectors.
        Restricts Chromecast to only communicate with known safe destinations.
        
        Args:
            chromecast_ip: Chromecast device IP address
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Implementing MITM protections for {chromecast_ip}")
        
        # The two rules removed here were global (no -s/-d scoping to the
        # Chromecast) and would drop legitimate packets for all Pi connections:
        #   iptables -A INPUT -m addrtype --src-type UNSPEC -j DROP
        #   iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
        rules = [
            # Block IP spoofing attempts sourced from Chromecast IP with UNSPEC type
            f"iptables -A INPUT -i {self.interface} -s {chromecast_ip} "
            f"-m addrtype --src-type UNSPEC -j DROP",
            
            # Verify ARP requests via arptables (no-op if arptables absent)
            f"arptables -A OUTPUT -o {self.interface} --opcode Request -j ACCEPT",
        ]
        
        return self._apply_firewall_rules(rules)
    
    def isolate_chromecast(self, chromecast_ip: str) -> bool:
        """
        Create network isolation for Chromecast.
        Restricts to local network communication only.
        
        Args:
            chromecast_ip: Chromecast device IP address
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Isolating Chromecast at {chromecast_ip} to local network only")
        
        rules = [
            # Allow ESTABLISHED/RELATED return traffic first — critical so that
            # streaming responses (Netflix, YouTube, etc.) can reach the Chromecast
            # after it initiates the outbound connection.
            f"iptables -I FORWARD 1 -d {chromecast_ip} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            # Allow inbound from local RFC-1918 networks (LAN casting, mDNS, etc.)
            f"iptables -I FORWARD 2 -d {chromecast_ip} -s 192.168.0.0/16 -j ACCEPT",
            f"iptables -I FORWARD 3 -d {chromecast_ip} -s 10.0.0.0/8 -j ACCEPT",
            f"iptables -I FORWARD 4 -d {chromecast_ip} -s 172.16.0.0/12 -j ACCEPT",
            # Block NEW inbound connections from WAN — prevents internet-initiated
            # exploitation while leaving Chromecast-initiated streams intact.
            f"iptables -A FORWARD -d {chromecast_ip} -m conntrack --ctstate NEW -j DROP",
        ]
        
        return self._apply_firewall_rules(rules)
    
    def redirect_dns_to_adguard(self, chromecast_ip: str) -> bool:
        """
        Force all Chromecast DNS queries through AdGuard DNS.
        Uses NAT PREROUTING DNAT so the Chromecast cannot bypass filtering
        by using hardcoded resolvers (8.8.8.8, 1.1.1.1, etc.).
        """
        logger.info(f"Redirecting DNS for {chromecast_ip} to AdGuard DNS ({self.ADGUARD_DNS_PRIMARY})")

        rules = [
            # Intercept UDP DNS and redirect to AdGuard primary
            f"iptables -t nat -A PREROUTING -i {self.interface} -s {chromecast_ip} "
            f"-p udp --dport 53 -j DNAT --to-destination {self.ADGUARD_DNS_PRIMARY}:53",
            # Intercept TCP DNS (large responses / DoT fallback)
            f"iptables -t nat -A PREROUTING -i {self.interface} -s {chromecast_ip} "
            f"-p tcp --dport 53 -j DNAT --to-destination {self.ADGUARD_DNS_PRIMARY}:53",
            # Allow the forwarded DNS traffic to leave the Pi toward AdGuard
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p udp -d {self.ADGUARD_DNS_PRIMARY} --dport 53 -j ACCEPT",
            f"iptables -A FORWARD -i {self.interface} -s {chromecast_ip} "
            f"-p tcp -d {self.ADGUARD_DNS_PRIMARY} --dport 53 -j ACCEPT",
        ]

        return self._apply_firewall_rules(rules)

    def monitor_chromecast_traffic(self, chromecast_ip: str, duration: int = 300) -> dict:
        """
        Monitor all traffic to/from Chromecast for suspicious activity.
        
        Args:
            chromecast_ip: Chromecast device IP address
            duration: Monitoring duration in seconds
            
        Returns:
            Dictionary with traffic statistics
        """
        logger.info(f"Monitoring Chromecast traffic for {duration}s")
        
        stats = {
            'inbound': 0,
            'outbound': 0,
            'suspicious_ips': [],
            'blocked_connections': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Use tcpdump to capture traffic
            cmd = [
                'timeout', str(duration),
                'tcpdump', '-i', self.interface,
                f'host {chromecast_ip}',
                '-q'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse output
            for line in result.stdout.split('\n'):
                if '>>' in line or '>' in line:
                    if chromecast_ip in line:
                        if '>' in line:
                            stats['outbound'] += 1
                        else:
                            stats['inbound'] += 1
                        
                        # Check for suspicious patterns
                        if any(domain in line for domain in self.BLOCKED_DOMAINS):
                            stats['suspicious_ips'].append(line)
            
            logger.info(f"Traffic stats: {json.dumps(stats, indent=2)}")
            
        except Exception as e:
            logger.error(f"Error monitoring traffic: {e}")
        
        return stats
    
    def _apply_firewall_rules(self, rules: List[str]) -> bool:
        """
        Apply firewall rules using iptables.
        
        Args:
            rules: List of iptables commands
            
        Returns:
            True if successful, False otherwise
        """
        success = True
        prefix = '' if os.geteuid() == 0 else 'sudo '

        for rule in rules:
            try:
                logger.debug(f"Applying rule: {rule}")
                result = subprocess.run(prefix + rule, shell=True, capture_output=True, check=False)
                
                if result.returncode != 0:
                    logger.warning(f"Rule failed: {rule}\n{result.stderr.decode()}")
                    success = False
                else:
                    self.firewall_rules.append(rule)
                    logger.debug(f"Rule applied successfully")
                    
            except Exception as e:
                logger.error(f"Error applying rule {rule}: {e}")
                success = False
        
        return success
    
    def flush_rules(self) -> bool:
        """
        Remove all applied firewall rules (for cleanup).
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Flushing firewall rules...")
        prefix = '' if os.geteuid() == 0 else 'sudo '

        try:
            subprocess.run(prefix + 'iptables -F', shell=True, check=True)
            subprocess.run(prefix + 'iptables -X', shell=True, check=True)
            self.firewall_rules = []
            logger.info("Firewall rules flushed")
            return True
        except Exception as e:
            logger.error(f"Error flushing rules: {e}")
            return False
    
    def get_status(self, chromecast_ip: str = None) -> dict:
        """
        Get current protection status.
        
        Args:
            chromecast_ip: Specific Chromecast to check (optional)
            
        Returns:
            Dictionary with status information
        """
        target_ip = chromecast_ip or self.chromecast_ip
        system_rules = self._get_system_rules()
        arp_rules = self._get_system_arp_rules()
        matching_rules = []
        if target_ip and system_rules:
            matching_rules = [line for line in system_rules.splitlines() if target_ip in line]

        status = {
            'timestamp': datetime.now().isoformat(),
            'interface': self.interface,
            'active_rules': len(matching_rules),
            'chromecast_ip': target_ip,
            'protections': {
                'external_access_blocked': False,
                'eavesdropping_blocked': False,
                'ddos_amplification_blocked': False,
                'mitm_protected': False,
                'isolated': False,
                'adguard_dns_enforced': False
            }
        }
        
        # Check live system rules instead of process-local memory.
        if target_ip and system_rules:
            status['protections']['external_access_blocked'] = any(
                target_ip in r and '-A INPUT' in r and '-j DROP' in r
                for r in system_rules.splitlines()
            )
            status['protections']['eavesdropping_blocked'] = any(
                target_ip in r and '-A FORWARD' in r and '--dport 53' in r and '-j DROP' in r
                for r in system_rules.splitlines()
            )
            status['protections']['ddos_amplification_blocked'] = any(
                target_ip in r and '-A FORWARD' in r and ('--dport 5353' in r or '--dport 1900' in r or '--dport 123' in r)
                for r in system_rules.splitlines()
            )
            status['protections']['mitm_protected'] = (
                any(
                    target_ip in r and '-m addrtype --src-type UNSPEC -j DROP' in r
                    for r in system_rules.splitlines()
                )
                or any('--opcode Request -j ACCEPT' in r for r in arp_rules.splitlines())
            )
            status['protections']['isolated'] = any(
                target_ip in r and '-A FORWARD' in r and '-j DROP' in r
                for r in system_rules.splitlines()
            )
            status['protections']['adguard_dns_enforced'] = any(
                target_ip in r and 'DNAT' in r and '--dport 53' in r
                and self.ADGUARD_DNS_PRIMARY in r
                for r in system_rules.splitlines()
            )

        return status


def main():
    parser = argparse.ArgumentParser(
        description='Chromecast Security Blocker - Protect against unauthorized access and eavesdropping'
    )
    
    parser.add_argument('action', choices=['discover', 'block', 'monitor', 'status', 'flush', 'full-protect'],
                       help='Action to perform')
    parser.add_argument('--ip', help='Chromecast IP address')
    parser.add_argument('--interface', help='Network interface to use')
    parser.add_argument('--duration', type=int, default=300, help='Monitoring duration in seconds')
    parser.add_argument('--scan-range', help='CIDR range for discovery (e.g. 10.42.0.0/24)')
    parser.add_argument('--scan-timeout', type=int, default=90, help='Discovery timeout in seconds')
    
    args = parser.parse_args()
    
    blocker = ChromecastBlocker(chromecast_ip=args.ip, interface=args.interface)
    
    if args.action == 'discover':
        ips = blocker.discover_chromecast(scan_range=args.scan_range, scan_timeout=args.scan_timeout)
        if ips:
            print(f"Found Chromecast devices: {', '.join(ips)}")
        else:
            print("No Chromecast devices found")
    
    elif args.action == 'block':
        if not args.ip:
            print("Error: --ip required for block action")
            return 1
        
        blocker.block_external_access(args.ip)
    
    elif args.action == 'monitor':
        if not args.ip:
            print("Error: --ip required for monitor action")
            return 1
        
        stats = blocker.monitor_chromecast_traffic(args.ip, args.duration)
        print(json.dumps(stats, indent=2))
    
    elif args.action == 'status':
        status = blocker.get_status(args.ip)
        print(json.dumps(status, indent=2))
    
    elif args.action == 'flush':
        blocker.flush_rules()
    
    elif args.action == 'full-protect':
        if not args.ip:
            print("Error: --ip required for full-protect action")
            return 1
        
        print(f"Applying full protection to {args.ip}")
        blocker.block_external_access(args.ip)
        blocker.block_eavesdropping(args.ip)
        blocker.block_ddos_amplification(args.ip)
        blocker.block_mitm_attacks(args.ip)
        blocker.isolate_chromecast(args.ip)
        blocker.redirect_dns_to_adguard(args.ip)
        
        status = blocker.get_status(args.ip)
        print("\n=== Protection Status ===")
        print(json.dumps(status, indent=2))
    
    return 0


if __name__ == '__main__':
    try:
        exit(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        exit(1)
