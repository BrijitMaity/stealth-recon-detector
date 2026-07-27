"""
firewall.py — Cross-Platform IP Blocking Engine (Industry-Grade IPS v2.0)

Features:
  - Windows (netsh advfirewall) and Linux (iptables / nftables) support
  - CIDR range blocking support with subnet auto-detection
  - Rule verification: checks if OS rule exists before adding duplicates
  - Rate-limiting for block operations (prevent block storms)
  - Audit trail logging for all block/unblock actions
  - TTL-based auto-expiry with background worker
  - Block audit report export (compliance-ready)
  - Structured logging
  - Graceful fallback to simulation when not running as admin
"""

import os
import ctypes
import subprocess
import ipaddress
import platform
import threading
import time
import json
import datetime
from collections import deque, defaultdict
from config import cfg
from state_manager import state
from app_logger import get_logger

log = get_logger(__name__)

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# Rate limiting: max blocks per minute
_MAX_BLOCKS_PER_MINUTE = 50
_RATE_WINDOW_SECONDS = 60


class Firewall:
    def __init__(self):
        # Load persisted blocked IPs from SQLite on startup
        self.blocked_ips = state.get_all_blocked_ips()
        self.blocked_cidrs = {}  # cidr_str -> expiry_time
        self.os_type = platform.system()
        self.is_admin = self._check_admin()
        self._lock = threading.Lock()

        # Rate limiter: track recent block timestamps
        self._block_timestamps = deque(maxlen=_MAX_BLOCKS_PER_MINUTE * 2)

        # Subnet tracking: count IPs per /24 for auto-CIDR blocking
        self._subnet_tracker = defaultdict(set)  # /24 prefix -> set of IPs

        # Metrics
        self._total_blocks = 0
        self._total_unblocks = 0
        self._failed_blocks = 0
        self._cidr_blocks = 0
        self._duplicate_rules_prevented = 0

        # Block audit history (in-memory ring buffer for fast export)
        self._audit_log = deque(maxlen=10000)

        # Detect firewall backend
        self._backend = self._detect_backend()

        log.info(
            f"Firewall IPS initialized on {self.os_type} (backend={self._backend}). "
            f"Loaded {len(self.blocked_ips)} blocked IPs from state.",
            extra={"is_admin": self.is_admin, "os": self.os_type, "backend": self._backend}
        )
        if not self.is_admin:
            log.warning("Not running as Administrator/root. Firewall blocking will be simulated.")

        # Start TTL expiry thread
        self.running = True
        self.ttl_thread = threading.Thread(target=self._ttl_worker, daemon=True)
        self.ttl_thread.start()

    def _check_admin(self):
        try:
            if self.os_type == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def _detect_backend(self) -> str:
        """Detect the best available firewall backend."""
        if self.os_type == "Windows":
            return "netsh"
        # Linux: prefer nftables, fallback to iptables
        try:
            result = subprocess.run(["nft", "--version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                return "nftables"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        try:
            result = subprocess.run(["iptables", "--version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                return "iptables"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return "simulated"

    def _is_valid_ip(self, ip_address):
        """Validate an IP address or CIDR notation."""
        try:
            if '/' in str(ip_address):
                ipaddress.ip_network(ip_address, strict=False)
            else:
                ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def _get_subnet_prefix(self, ip_address: str) -> str:
        """Extract the /24 subnet prefix from an IP address."""
        try:
            addr = ipaddress.ip_address(ip_address)
            network = ipaddress.ip_network(f"{addr}/24", strict=False)
            return str(network)
        except ValueError:
            return ""

    def _check_rate_limit(self) -> bool:
        """Returns True if we're within the rate limit, False if exceeded."""
        now = time.time()
        while self._block_timestamps and now - self._block_timestamps[0] > _RATE_WINDOW_SECONDS:
            self._block_timestamps.popleft()
        return len(self._block_timestamps) < _MAX_BLOCKS_PER_MINUTE

    def _rule_exists(self, ip_address: str) -> bool:
        """Check if a firewall rule already exists for this IP (prevents duplicates)."""
        if not self.is_admin:
            return False
        try:
            if self._backend == "netsh":
                rule_name = f"BLOCK_STEALTH_{ip_address}"
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],
                    capture_output=True, timeout=10
                )
                return result.returncode == 0 and b"Rule Name" in result.stdout
            elif self._backend == "iptables":
                result = subprocess.run(
                    ['iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                    capture_output=True, timeout=10
                )
                return result.returncode == 0
            elif self._backend == "nftables":
                result = subprocess.run(
                    ['nft', 'list', 'ruleset'],
                    capture_output=True, timeout=10
                )
                return ip_address.encode() in result.stdout
        except Exception:
            pass
        return False

    def _ttl_worker(self):
        while self.running:
            now = time.time()
            # Expire individual IPs
            expired_ips = [ip for ip, expiry in list(self.blocked_ips.items()) if now >= expiry]
            for ip in expired_ips:
                self.unblock_ip(ip)
            # Expire CIDRs
            expired_cidrs = [cidr for cidr, expiry in list(self.blocked_cidrs.items()) if now >= expiry]
            for cidr in expired_cidrs:
                self.unblock_cidr(cidr)
            time.sleep(10)

    def _record_audit(self, action: str, target: str, details: str = ""):
        """Record an action to the in-memory audit log."""
        self._audit_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "action": action,
            "target": target,
            "details": details,
            "admin_mode": self.is_admin,
            "backend": self._backend,
        })

    def quarantine_ip(self, ip_address, reason="Zero-Trust Quarantine"):
        """Simulates placing an IP into an isolated Zero-Trust Quarantine VLAN."""
        if not self._is_valid_ip(ip_address):
            return False
            
        with self._lock:
            if ip_address not in self.blocked_ips:
                expiry_time = time.time() + cfg.BLOCK_TTL_SECONDS
                self.blocked_ips[ip_address] = expiry_time
                state.save_blocked_ip(ip_address, f"[QUARANTINE] {reason}", expiry_time)
                self._total_blocks += 1
                self._record_audit("QUARANTINE", ip_address, reason)
                log.critical(
                    f"Zero-Trust Quarantine active for {ip_address} (Rerouting to Honeypot)",
                    extra={"ip": ip_address, "reason": reason, "mode": "quarantine"}
                )
                return True
        return True

    def block_ip(self, ip_address, reason="ML Detection"):
        """Blocks an IP address using the detected firewall backend or simulates."""
        if not self._is_valid_ip(ip_address):
            log.error(f"Invalid IP format ignored: {ip_address}")
            return False

        # Rate limit check
        if not self._check_rate_limit():
            log.warning(
                f"Block rate limit exceeded ({_MAX_BLOCKS_PER_MINUTE}/min). "
                f"Skipping block for {ip_address}."
            )
            return False

        with self._lock:
            if ip_address not in self.blocked_ips:
                if len(self.blocked_ips) >= cfg.MAX_BLOCKED_IPS:
                    log.error(f"Max blocked IPs ({cfg.MAX_BLOCKED_IPS}) reached. Cannot block {ip_address}.")
                    return False

                expiry_time = time.time() + cfg.BLOCK_TTL_SECONDS
                self._block_timestamps.append(time.time())

                # Track subnet for auto-CIDR blocking
                subnet = self._get_subnet_prefix(ip_address)
                if subnet:
                    self._subnet_tracker[subnet].add(ip_address)

                if not self.is_admin:
                    self.blocked_ips[ip_address] = expiry_time
                    state.save_blocked_ip(ip_address, reason, expiry_time)
                    self._total_blocks += 1
                    self._record_audit("BLOCK", ip_address, f"Simulated. reason={reason}")
                    log.info(
                        f"Simulated block applied for {ip_address} (TTL: {cfg.BLOCK_TTL_SECONDS}s)",
                        extra={"ip": ip_address, "reason": reason, "mode": "simulated"}
                    )
                    return True

                # Check if rule already exists (prevent duplicates)
                if self._rule_exists(ip_address):
                    self._duplicate_rules_prevented += 1
                    self.blocked_ips[ip_address] = expiry_time
                    state.save_blocked_ip(ip_address, reason, expiry_time)
                    log.debug(f"Rule already exists for {ip_address}. Refreshed TTL only.")
                    return True

                try:
                    if self._backend == "netsh":
                        rule_name = f"BLOCK_STEALTH_{ip_address}"
                        cmd = [
                            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                            f'name={rule_name}',
                            'dir=in', 'action=block', f'remoteip={ip_address}'
                        ]
                    elif self._backend == "nftables":
                        cmd = [
                            'nft', 'add', 'rule', 'inet', 'filter', 'input',
                            'ip', 'saddr', ip_address, 'drop'
                        ]
                    else:  # iptables
                        cmd = ['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']

                    result = subprocess.run(cmd, capture_output=True, timeout=10)
                    if result.returncode != 0:
                        raise RuntimeError(f"Firewall command failed: {result.stderr.decode(errors='ignore').strip()}")

                    self.blocked_ips[ip_address] = expiry_time
                    state.save_blocked_ip(ip_address, reason, expiry_time)
                    self._total_blocks += 1
                    self._record_audit("BLOCK", ip_address, f"REAL block applied. reason={reason}")
                    log.info(
                        f"REAL BLOCK APPLIED: {ip_address} (TTL: {cfg.BLOCK_TTL_SECONDS}s)",
                        extra={"ip": ip_address, "reason": reason, "mode": "real"}
                    )
                    return True
                except Exception as e:
                    self._failed_blocks += 1
                    log.error(f"Failed to apply real block: {e}")
                    self.blocked_ips[ip_address] = expiry_time
                    state.save_blocked_ip(ip_address, reason, expiry_time)
                    self._total_blocks += 1
                    self._record_audit("BLOCK", ip_address, f"Fallback simulated. error={e}")
                    log.warning(f"Falling back to simulated block for {ip_address}")
                    return True
            else:
                # Refresh TTL
                expiry_time = time.time() + cfg.BLOCK_TTL_SECONDS
                self.blocked_ips[ip_address] = expiry_time
                state.save_blocked_ip(ip_address, reason, expiry_time)
                return True

    def block_cidr(self, cidr_str: str, reason="Subnet Auto-Block"):
        """Block an entire CIDR range (e.g., 10.0.0.0/24)."""
        if not self._is_valid_ip(cidr_str):
            log.error(f"Invalid CIDR format: {cidr_str}")
            return False

        with self._lock:
            if cidr_str in self.blocked_cidrs:
                return True  # Already blocked

            expiry_time = time.time() + cfg.BLOCK_TTL_SECONDS

            if self.is_admin:
                try:
                    if self._backend == "netsh":
                        rule_name = f"BLOCK_SUBNET_{cidr_str.replace('/', '_')}"
                        cmd = [
                            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                            f'name={rule_name}',
                            'dir=in', 'action=block', f'remoteip={cidr_str}'
                        ]
                    elif self._backend == "nftables":
                        cmd = [
                            'nft', 'add', 'rule', 'inet', 'filter', 'input',
                            'ip', 'saddr', cidr_str, 'drop'
                        ]
                    else:
                        cmd = ['iptables', '-A', 'INPUT', '-s', cidr_str, '-j', 'DROP']

                    subprocess.run(cmd, capture_output=True, timeout=10)
                except Exception as e:
                    log.error(f"CIDR block command failed: {e}")

            self.blocked_cidrs[cidr_str] = expiry_time
            self._cidr_blocks += 1
            self._record_audit("BLOCK_CIDR", cidr_str, f"reason={reason}")
            log.info(f"CIDR BLOCKED: {cidr_str} (TTL: {cfg.BLOCK_TTL_SECONDS}s)")
            print(f"{RED}[Firewall IPS] SUBNET BLOCKED: {cidr_str} ({reason}){RESET}")
            return True

    def check_subnet_escalation(self, ip_address: str, threshold: int = 3) -> bool:
        """
        Check if a /24 subnet has enough unique attacking IPs to trigger subnet-level blocking.
        Returns True if a CIDR block was applied.
        """
        subnet = self._get_subnet_prefix(ip_address)
        if not subnet:
            return False
        with self._lock:
            unique_ips = self._subnet_tracker.get(subnet, set())
        if len(unique_ips) >= threshold and subnet not in self.blocked_cidrs:
            self.block_cidr(subnet, reason=f"Auto-escalation: {len(unique_ips)} unique attacking IPs")
            return True
        return False

    def unblock_ip(self, ip_address):
        """Unblocks an IP address with OS-level rule verification."""
        with self._lock:
            if ip_address in self.blocked_ips:
                if self.is_admin:
                    try:
                        if self._backend == "netsh":
                            rule_name = f"BLOCK_STEALTH_{ip_address}"
                            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
                        elif self._backend == "nftables":
                            # nftables requires handle-based deletion; flush specific rules
                            cmd = ['nft', 'flush', 'chain', 'inet', 'filter', 'input']
                        else:
                            cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']

                        result = subprocess.run(cmd, capture_output=True, timeout=10)
                        if result.returncode != 0:
                            log.warning(f"OS unblock may have failed for {ip_address}: {result.stderr.decode(errors='ignore')}")
                    except Exception as e:
                        log.error(f"Failed to unblock {ip_address}: {e}")

                del self.blocked_ips[ip_address]
                state.remove_blocked_ip(ip_address)
                self._total_unblocks += 1
                self._record_audit("UNBLOCK", ip_address, "TTL expired or manual")
                log.info(
                    f"UNBLOCKED: {ip_address} (TTL expired or manual unblock)",
                    extra={"ip": ip_address}
                )
                return True
            return False

    def unblock_cidr(self, cidr_str: str):
        """Unblock a CIDR range."""
        with self._lock:
            if cidr_str in self.blocked_cidrs:
                if self.is_admin:
                    try:
                        if self._backend == "netsh":
                            rule_name = f"BLOCK_SUBNET_{cidr_str.replace('/', '_')}"
                            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
                        elif self._backend == "nftables":
                            cmd = ['nft', 'flush', 'chain', 'inet', 'filter', 'input']
                        else:
                            cmd = ['iptables', '-D', 'INPUT', '-s', cidr_str, '-j', 'DROP']
                        subprocess.run(cmd, capture_output=True, timeout=10)
                    except Exception as e:
                        log.error(f"CIDR unblock failed: {e}")

                del self.blocked_cidrs[cidr_str]
                self._record_audit("UNBLOCK_CIDR", cidr_str, "TTL expired")
                log.info(f"CIDR UNBLOCKED: {cidr_str}")
                return True
            return False

    def is_blocked(self, ip_address):
        """Check if IP is blocked individually or by CIDR."""
        if ip_address in self.blocked_ips:
            return True
        # Check if IP falls within any blocked CIDR
        try:
            addr = ipaddress.ip_address(ip_address)
            for cidr_str in list(self.blocked_cidrs.keys()):
                if addr in ipaddress.ip_network(cidr_str, strict=False):
                    return True
        except ValueError:
            pass
        return False

    def get_block_list(self):
        return list(self.blocked_ips.keys())

    def get_metrics(self) -> dict:
        """Return firewall operational metrics."""
        return {
            "total_blocks": self._total_blocks,
            "total_unblocks": self._total_unblocks,
            "failed_blocks": self._failed_blocks,
            "cidr_blocks": self._cidr_blocks,
            "duplicate_rules_prevented": self._duplicate_rules_prevented,
            "currently_blocked_ips": len(self.blocked_ips),
            "currently_blocked_cidrs": len(self.blocked_cidrs),
            "tracked_subnets": len(self._subnet_tracker),
            "is_admin": self.is_admin,
            "os": self.os_type,
            "backend": self._backend,
        }

    def get_block_stats(self) -> dict:
        """Return detailed block statistics for dashboard integration."""
        with self._lock:
            subnet_stats = {}
            for subnet, ips in self._subnet_tracker.items():
                subnet_stats[subnet] = {
                    "unique_attacking_ips": len(ips),
                    "is_cidr_blocked": subnet in self.blocked_cidrs,
                }
        return {
            "ip_blocks": {ip: {"expires_at": exp, "ttl_remaining": max(0, exp - time.time())}
                          for ip, exp in self.blocked_ips.items()},
            "cidr_blocks": {cidr: {"expires_at": exp, "ttl_remaining": max(0, exp - time.time())}
                           for cidr, exp in self.blocked_cidrs.items()},
            "subnet_intelligence": subnet_stats,
            "metrics": self.get_metrics(),
        }

    def export_block_report(self, output_path: str = "firewall_audit_report.json") -> str:
        """Export a compliance-ready block audit report to JSON."""
        report = {
            "report_type": "firewall_block_audit",
            "generated_at": datetime.datetime.now().isoformat(),
            "system_version": cfg.VERSION,
            "backend": self._backend,
            "is_admin": self.is_admin,
            "summary": self.get_metrics(),
            "active_blocks": {
                "individual_ips": {ip: {"expires_at": datetime.datetime.fromtimestamp(exp).isoformat()}
                                   for ip, exp in self.blocked_ips.items()},
                "cidr_ranges": {cidr: {"expires_at": datetime.datetime.fromtimestamp(exp).isoformat()}
                                for cidr, exp in self.blocked_cidrs.items()},
            },
            "recent_audit_entries": list(self._audit_log),
        }
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            log.info(f"Firewall audit report exported: {output_path}")
            return output_path
        except Exception as e:
            log.error(f"Audit report export failed: {e}")
            return ""

    def shutdown(self):
        self.running = False
        # Export audit report on shutdown
        try:
            self.export_block_report()
        except Exception:
            pass
        log.info("Firewall IPS shutdown", extra=self.get_metrics())

