"""
threat_intel.py — External Threat Intelligence Feed Integration
"""

import threading
import time
import requests
from app_logger import get_logger

log = get_logger(__name__)

class ThreatIntel:
    def __init__(self):
        self.malicious_ips = set()
        self.lock = threading.Lock()
        self.feed_urls = [
            # A lightweight and reliable public blocklist for demo purposes
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        ]
        self.update_interval = 3600  # Refresh every hour
        
        # Start background update thread
        threading.Thread(target=self._update_loop, daemon=True).start()

    def _update_loop(self):
        while True:
            self._fetch_feeds()
            time.sleep(self.update_interval)

    def _fetch_feeds(self):
        new_ips = set()
        for url in self.feed_urls:
            try:
                log.info(f"ThreatIntel: Fetching IOCs from {url}")
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        line = line.strip()
                        # Ignore comments and empty lines
                        if line and not line.startswith('#'):
                            new_ips.add(line)
            except Exception as e:
                log.error(f"ThreatIntel: Failed to fetch {url}: {e}")
        
        with self.lock:
            if new_ips:
                self.malicious_ips = new_ips
                log.info(f"ThreatIntel: Successfully loaded {len(self.malicious_ips)} known malicious IPs.")
            else:
                log.warning("ThreatIntel: Feed update returned 0 IPs.")

    def is_known_bad(self, ip: str) -> bool:
        """Check if an IP is in the known malicious list."""
        with self.lock:
            return ip in self.malicious_ips

threat_intel = ThreatIntel()
