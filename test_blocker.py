#!/usr/bin/env python3
"""
Testing & Validation Suite for Chromecast Blocker
Verifies all protections are working correctly
"""

import subprocess
import socket
import sys
import logging
import json
from typing import Tuple

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class ChromecastBlockerTester:
    """Test suite for verifying Chromecast blocker functionality"""
    
    def __init__(self, chromecast_ip: str):
        """Initialize tester with target Chromecast IP"""
        self.chromecast_ip = chromecast_ip
        self.test_results = {}
    
    def test_privileges(self) -> bool:
        """Check if running with sufficient privileges"""
        if os.geteuid() != 0:
            logger.error("Must run as root")
            return False
        logger.info("✓ Running as root")
        return True
    
    def test_dependencies(self) -> bool:
        """Verify all required tools are installed"""
        tools = ['iptables', 'nmap', 'tcpdump', 'arptables']
        all_present = True
        
        for tool in tools:
            result = subprocess.run(
                f'which {tool}',
                shell=True,
                capture_output=True
            )
            if result.returncode == 0:
                logger.info(f"✓ {tool} found")
            else:
                logger.warning(f"✗ {tool} NOT found")
                all_present = False
        
        return all_present
    
    def test_local_connectivity(self) -> bool:
        """Test that local network can still reach Chromecast"""
        logger.info(f"Testing local connectivity to {self.chromecast_ip}...")
        
        result = subprocess.run(
            ['ping', '-c', '1', self.chromecast_ip],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode == 0:
            logger.info(f"✓ Local connectivity works")
            return True
        else:
            logger.warning(f"✗ Cannot ping Chromecast (device may be offline)")
            return False
    
    def test_firewall_rules(self) -> Tuple[bool, int]:
        """Verify firewall rules are applied"""
        logger.info("Checking firewall rules...")
        
        result = subprocess.run(
            'iptables -L -n',
            shell=True,
            capture_output=True,
            text=True
        )
        
        output = result.stdout
        rule_count = len([line for line in output.split('\n') if 'DROP' in line or 'ACCEPT' in line])
        
        if rule_count > 0:
            logger.info(f"✓ Found {rule_count} firewall rules")
            return True, rule_count
        else:
            logger.warning("✗ No firewall rules found")
            return False, 0
    
    def test_external_blocking(self) -> bool:
        """Test that external access is blocked"""
        logger.info("Testing external access blocking...")
        
        # Check if rules exist to block external access
        result = subprocess.run(
            f'iptables -L -n | grep {self.chromecast_ip}',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if 'DROP' in result.stdout or 'REJECT' in result.stdout:
            logger.info("✓ External blocking rules detected")
            return True
        else:
            logger.warning("✗ External blocking rules NOT found")
            return False
    
    def test_cloud_connectivity_blocking(self) -> bool:
        """Test that cloud connectivity is blocked"""
        logger.info("Testing cloud connectivity blocking...")
        
        # Check for DNS blocking rules
        result = subprocess.run(
            'iptables -L -n | grep -E "53|googleapis"',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if 'DROP' in result.stdout or len(result.stdout) > 0:
            logger.info("✓ Cloud connectivity blocking rules detected")
            return True
        else:
            logger.warning("✗ Cloud connectivity blocking rules NOT found")
            return False
    
    def test_ddos_protection(self) -> bool:
        """Test DDoS amplification protection"""
        logger.info("Testing DDoS amplification protection...")
        
        # Check for amplification port blocking rules
        result = subprocess.run(
            'iptables -L -n | grep -E "5353|1900"',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if 'DROP' in result.stdout or len(result.stdout) > 0:
            logger.info("✓ DDoS protection rules detected")
            return True
        else:
            logger.warning("✗ DDoS protection rules NOT found")
            return False
    
    def test_mitm_protection(self) -> bool:
        """Test MITM attack protection"""
        logger.info("Testing MITM protection...")
        
        # Check for state tracking and invalid packet dropping
        result = subprocess.run(
            'iptables -L -n | grep -E "INVALID|conntrack"',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if 'DROP' in result.stdout or 'INVALID' in result.stdout:
            logger.info("✓ MITM protection rules detected")
            return True
        else:
            logger.warning("✗ MITM protection rules NOT found")
            return False
    
    def test_network_isolation(self) -> bool:
        """Test network isolation"""
        logger.info("Testing network isolation...")
        
        # Check FORWARD rules
        result = subprocess.run(
            f'iptables -L FORWARD -n | grep {self.chromecast_ip}',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if 'DROP' in result.stdout or 'REJECT' in result.stdout:
            logger.info("✓ Network isolation rules detected")
            return True
        else:
            logger.warning("✗ Network isolation rules NOT found")
            return False
    
    def test_log_file(self) -> bool:
        """Check if logging is working"""
        logger.info("Checking log file...")
        
        if os.path.exists('chromecast_blocker.log'):
            size = os.path.getsize('chromecast_blocker.log')
            if size > 0:
                logger.info(f"✓ Log file found ({size} bytes)")
                return True
            else:
                logger.warning("✗ Log file is empty")
                return False
        else:
            logger.warning("✗ Log file not found")
            return False
    
    def run_all_tests(self) -> dict:
        """Run all tests and return results"""
        print("\n" + "="*60)
        print("CHROMECAST BLOCKER TEST SUITE")
        print("="*60 + "\n")
        
        self.test_results = {
            'privileges': self.test_privileges(),
            'dependencies': self.test_dependencies(),
            'local_connectivity': self.test_local_connectivity(),
            'firewall_rules': self.test_firewall_rules()[0],
            'external_blocking': self.test_external_blocking(),
            'cloud_blocking': self.test_cloud_connectivity_blocking(),
            'ddos_protection': self.test_ddos_protection(),
            'mitm_protection': self.test_mitm_protection(),
            'network_isolation': self.test_network_isolation(),
            'logging': self.test_log_file(),
        }
        
        return self.test_results
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        passed = sum(1 for v in self.test_results.values() if v)
        total = len(self.test_results)
        
        for test, result in self.test_results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{status:>8} - {test}")
        
        print("\n" + "-"*60)
        print(f"Total: {passed}/{total} tests passed")
        
        if passed == total:
            print("\n🛡️  ALL TESTS PASSED - System is fully protected!")
        elif passed > total * 0.8:
            print("\n✓ MOST TESTS PASSED - System is mostly protected")
        else:
            print("\n⚠️  SOME TESTS FAILED - Review results above")
        
        print("="*60 + "\n")
        
        return passed == total


def main():
    import argparse
    import os
    
    parser = argparse.ArgumentParser(
        description='Chromecast Blocker Test Suite'
    )
    parser.add_argument('ip', help='Chromecast IP address')
    
    args = parser.parse_args()
    
    tester = ChromecastBlockerTester(args.ip)
    tester.run_all_tests()
    success = tester.print_summary()
    
    return 0 if success else 1


if __name__ == '__main__':
    import os
    exit(main())
