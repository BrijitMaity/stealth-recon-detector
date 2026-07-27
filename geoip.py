import time
import requests
import threading
from collections import OrderedDict
from app_logger import get_logger

log = get_logger(__name__)

class GeoIPResolver:
    def __init__(self, cache_size=5000):
        self._cache = OrderedDict()
        self._maxsize = cache_size
        self._lock = threading.Lock()
        # Ensure we don't spam the free API (45 requests per min)
        self._last_request_time = 0
        self._min_delay = 1.4  # seconds

    def resolve(self, ip_address):
        """Resolves IP to Lat/Lon coordinates using ip-api.com"""
        # Exclude private IPs
        if ip_address.startswith("10.") or ip_address.startswith("192.168.") or ip_address.startswith("172.") or ip_address == "127.0.0.1":
            return {"lat": 37.7749, "lon": -122.4194, "city": "Local Network"} # Default to SF for local

        with self._lock:
            if ip_address in self._cache:
                self._cache.move_to_end(ip_address)
                return self._cache[ip_address]

            # Rate limit
            now = time.time()
            if now - self._last_request_time < self._min_delay:
                time.sleep(self._min_delay - (now - self._last_request_time))
            self._last_request_time = time.time()

        try:
            resp = requests.get(f"http://ip-api.com/json/{ip_address}?fields=lat,lon,city", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("lat") and data.get("lon"):
                    result = {"lat": data["lat"], "lon": data["lon"], "city": data.get("city", "Unknown")}
                else:
                    # Random fallback coordinates if lookup fails
                    result = {"lat": 34.0522, "lon": -118.2437, "city": "Unknown"}
            else:
                result = {"lat": 34.0522, "lon": -118.2437, "city": "Unknown"}
        except Exception as e:
            log.warning(f"GeoIP resolution failed for {ip_address}: {e}")
            result = {"lat": 34.0522, "lon": -118.2437, "city": "Unknown"}

        with self._lock:
            self._cache[ip_address] = result
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)

        return result

geoip_resolver = GeoIPResolver()
