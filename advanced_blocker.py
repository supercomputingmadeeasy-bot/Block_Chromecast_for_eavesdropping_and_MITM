#!/usr/bin/env python3
"""
Advanced Chromecast Blocker with Config File Support
Provides additional protection mechanisms and monitoring
"""

import yaml
import subprocess
import signal
import sys
import time
from typing import Dict, List
import logging
from pathlib import Path
from chromecast_blocker import ChromecastBlocker

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AdvancedChromecastBlocker(ChromecastBlocker):
    """Extended blocker with config file and continuous monitoring support"""
    
    def __init__(self, config_file: str = 'config.yaml'):
        """
        Initialize with configuration file.
        
        Args:
            config_file: Path to YAML configuration file
        """
        self.config_file = config_file
        self.config = self._load_config()
        self.monitoring = False
        
        super().__init__(
            interface=self.config.get('network_interface', 'eth0')
        )
    
    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {self.config_file}")
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_file}")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML: {e}")
            return {}
    
    def protect_all_devices(self):
        """Apply protections to all configured devices"""
        devices = self.config.get('chromecast_devices', [])

        if not devices:
            logger.warning("No devices configured in config.yaml")
            return

        # Apply DNS rate-limit overrides from config before protecting devices.
        dns_cfg = self.config.get('dns_rate_limits', {})
        if dns_cfg:
            import chromecast_blocker as _cb_mod
            # Patch class-level defaults so block_ddos_amplification() picks them up
            self._dns_udp_limit   = dns_cfg.get('udp_limit_per_min', 300)
            self._dns_udp_burst   = dns_cfg.get('udp_burst', 60)
            self._dns_tcp_limit   = dns_cfg.get('tcp_limit_per_min', 60)
            self._dns_tcp_burst   = dns_cfg.get('tcp_burst', 20)
            self._mdns_limit      = dns_cfg.get('mdns_limit_per_min', 5)
            self._mdns_burst      = dns_cfg.get('mdns_burst', 15)
            logger.info(
                f"DNS rate limits from config: UDP {self._dns_udp_limit}/min burst {self._dns_udp_burst}, "
                f"TCP {self._dns_tcp_limit}/min burst {self._dns_tcp_burst}"
            )

        for device in devices:
            if not device.get('enabled', True):
                logger.info(f"Skipping disabled device: {device.get('name')}")
                continue

            ip = device.get('ip')
            name = device.get('name', ip)

            logger.info(f"Protecting {name} at {ip}")
            self.chromecast_ip = ip

            blocking_config = self.config.get('blocking', {})

            if blocking_config.get('block_external', True):
                self.block_external_access(ip)

            if blocking_config.get('block_eavesdropping', True):
                self.block_eavesdropping(ip)

            if blocking_config.get('block_ddos_amplification', True):
                self.block_ddos_amplification(ip)

            if blocking_config.get('block_mitm', True):
                self.block_mitm_attacks(ip)

            if blocking_config.get('isolate_local_only', True):
                self.isolate_chromecast(ip)

            # Allow Cast SDK / infrastructure domains so that Cast receiver apps
            # (TV2 Play DK, etc.) can load and authenticate even when broad Google
            # IP subnet drops are in place.  Rules are inserted at FORWARD position
            # 1 and are idempotent (skipped if already present).
            cast_cfg = self.config.get('cast_sdk_allowlist', {})
            if cast_cfg.get('enabled', False):
                domains = cast_cfg.get('domains', [])
                if domains:
                    self.allow_cast_domains(ip, domains)
    
    def continuous_monitor(self, interval: int = 60):
        """
        Continuously monitor all devices for suspicious activity.
        
        Args:
            interval: Monitoring interval in seconds
        """
        def signal_handler(sig, frame):
            logger.info("Stopping monitoring...")
            self.monitoring = False
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        self.monitoring = True
        devices = self.config.get('chromecast_devices', [])
        
        logger.info(f"Starting continuous monitoring with {interval}s interval")
        
        while self.monitoring:
            for device in devices:
                if not device.get('enabled', True):
                    continue
                
                ip = device.get('ip')
                name = device.get('name', ip)
                
                try:
                    stats = self.monitor_chromecast_traffic(ip, duration=5)
                    
                    if stats.get('suspicious_ips'):
                        logger.warning(f"Suspicious activity detected on {name}: {stats['suspicious_ips']}")
                    
                except Exception as e:
                    logger.error(f"Error monitoring {name}: {e}")
            
            time.sleep(interval)
    
    def get_protection_summary(self) -> str:
        """Get a summary of all protections"""
        devices = self.config.get('chromecast_devices', [])
        summary = "=== Chromecast Protection Summary ===\n"
        
        for device in devices:
            if not device.get('enabled', True):
                continue
            
            ip = device.get('ip')
            name = device.get('name', ip)
            
            status = self.get_status(ip)
            protections = status.get('protections', {})
            
            summary += f"\n{name} ({ip}):\n"
            summary += f"  External access blocked: {protections.get('external_access_blocked')}\n"
            summary += f"  Eavesdropping blocked: {protections.get('eavesdropping_blocked')}\n"
            summary += f"  DDoS amplification blocked: {protections.get('ddos_amplification_blocked')}\n"
            summary += f"  MITM protected: {protections.get('mitm_protected')}\n"
            summary += f"  Network isolated: {protections.get('isolated')}\n"
        
        return summary
    
    def export_rules(self, output_file: str):
        """Export all firewall rules for backup"""
        logger.info(f"Exporting firewall rules to {output_file}")
        
        try:
            result = subprocess.run(
                'iptables-save',
                capture_output=True,
                text=True,
                check=True
            )
            
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            
            logger.info(f"Rules exported successfully to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting rules: {e}")
    
    def import_rules(self, input_file: str):
        """Import firewall rules from backup"""
        logger.info(f"Importing firewall rules from {input_file}")
        
        try:
            with open(input_file, 'r') as f:
                rules = f.read()
            
            result = subprocess.run(
                'iptables-restore',
                input=rules,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info("Rules imported successfully")
            else:
                logger.error(f"Error importing rules: {result.stderr}")
        except Exception as e:
            logger.error(f"Error importing rules: {e}")
    
    def rotate_logs(self):
        """Rotate log files to prevent unbounded growth"""
        log_config = self.config.get('logging', {})
        log_file = log_config.get('file', 'chromecast_blocker.log')
        max_size_mb = log_config.get('max_size_mb', 10)
        backup_count = log_config.get('backup_count', 5)
        
        try:
            log_path = Path(log_file)
            
            if log_path.exists():
                size_mb = log_path.stat().st_size / (1024 * 1024)
                
                if size_mb > max_size_mb:
                    # Rotate logs
                    for i in range(backup_count - 1, 0, -1):
                        old_file = Path(f"{log_file}.{i}")
                        new_file = Path(f"{log_file}.{i + 1}")
                        
                        if old_file.exists():
                            old_file.rename(new_file)
                    
                    # Move current to .1
                    log_path.rename(Path(f"{log_file}.1"))
                    logger.info(f"Rotated log file (was {size_mb:.1f}MB)")
        except Exception as e:
            logger.error(f"Error rotating logs: {e}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced Chromecast Security Blocker with Config Support'
    )
    
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file (default: config.yaml)')
    parser.add_argument('action', choices=['protect-all', 'monitor', 'summary', 'export', 'import', 'rotate-logs'],
                       help='Action to perform')
    parser.add_argument('--output', help='Output file for export')
    parser.add_argument('--input', help='Input file for import')
    parser.add_argument('--interval', type=int, default=60,
                       help='Monitoring interval in seconds')
    
    args = parser.parse_args()
    
    blocker = AdvancedChromecastBlocker(config_file=args.config)
    
    try:
        if args.action == 'protect-all':
            print("Applying protections to all configured devices...")
            blocker.protect_all_devices()
            print(blocker.get_protection_summary())
        
        elif args.action == 'monitor':
            blocker.continuous_monitor(interval=args.interval)
        
        elif args.action == 'summary':
            print(blocker.get_protection_summary())
        
        elif args.action == 'export':
            if not args.output:
                print("Error: --output required for export")
                return 1
            blocker.export_rules(args.output)
        
        elif args.action == 'import':
            if not args.input:
                print("Error: --input required for import")
                return 1
            blocker.import_rules(args.input)
        
        elif args.action == 'rotate-logs':
            blocker.rotate_logs()
        
        return 0
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    exit(main())
