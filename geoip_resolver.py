"""
geoip_resolver.py — Resolves IP addresses to geographical locations using ipapi.co
Features LRU caching and private IP handling to minimize API calls.
"""

import requests
import time
import ipaddress
import threading
from functools import lru_cache
from config import cfg
from app_logger import get_logger

log = get_logger(__name__)

class GeoIPResolver:
    def __init__(self):
        self.api_url = cfg.GEOIP_API_URL
        self.cache_ttl = cfg.GEOIP_CACHE_TTL
        self._cache = {}
        self._lock = threading.Lock()

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_unspecified
        except ValueError:
            return True

    def resolve(self, ip: str) -> dict:
        """
        Returns a dict with 'country', 'city', 'lat', 'lon'.
        Uses thread-safe caching.
        """
        if self._is_private_ip(ip):
            return {"country": "Local", "city": "Internal", "lat": 0.0, "lon": 0.0}

        now = time.time()
        
        with self._lock:
            cached = self._cache.get(ip)
            if cached and (now - cached['ts'] < self.cache_ttl):
                return cached['data']

        try:
            # Using ipapi.co free tier (max 1000/day without auth)
            headers = {"User-Agent": "StealthSOC/2.0"}
            resp = requests.get(f"{self.api_url}/{ip}/json/", headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if "error" not in data:
                    result = {
                        "country": data.get("country_name", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("latitude", 0.0),
                        "lon": data.get("longitude", 0.0)
                    }
                    
                    with self._lock:
                        self._cache[ip] = {"data": result, "ts": now}
                        
                    return result
            elif resp.status_code == 429:
                log.warning("GeoIP API rate limit reached.")
        except Exception as e:
            log.warning(f"GeoIP resolution failed for {ip}: {e}")

        # Fallback empty
        result = {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}
        with self._lock:
            # Cache failure for 5 mins to prevent spamming
            self._cache[ip] = {"data": result, "ts": now - self.cache_ttl + 300}
        return result

geoip_resolver = GeoIPResolver()
