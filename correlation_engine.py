"""
correlation_engine.py — Log Correlation Engine

Detects multi-stage attacks by correlating events across time windows for the same IP.
"""

import time
import threading
from collections import defaultdict
from config import cfg
from app_logger import get_logger

log = get_logger(__name__)

class CorrelationEngine:
    def __init__(self):
        self.window = cfg.CORRELATION_WINDOW_SECONDS
        self.min_stages = cfg.CORRELATION_MIN_STAGES
        # IP -> list of {"ts": float, "tactic": str}
        self.history = defaultdict(list)
        self._lock = threading.Lock()

    def process_event(self, event: dict) -> dict:
        """
        Analyzes the event against recent history for the same IP.
        Returns the event (possibly with elevated severity and updated tactic).
        """
        src_ip = event.get('src_ip')
        tactic = event.get('mitre_tactic', 'Unknown')
        severity = event.get('severity', 0.0)
        
        if not src_ip or src_ip == "127.0.0.1" or severity == 0:
            return event

        now = time.time()
        
        with self._lock:
            # Clean up old events for this IP
            self.history[src_ip] = [e for e in self.history[src_ip] if now - e['ts'] <= self.window]
            
            # Record this event
            self.history[src_ip].append({"ts": now, "tactic": tactic})
            
            # Correlate
            unique_tactics = set(e['tactic'] for e in self.history[src_ip] if e['tactic'] != 'Unknown')
            
            # If we see multiple stages (e.g. Discovery -> Credential Access -> Lateral Movement)
            if len(unique_tactics) >= self.min_stages:
                log.warning(f"CORRELATION ALERT: Multi-stage attack detected from {src_ip}: {unique_tactics}")
                event['mitre_tactic'] = f"Multi-Stage: {', '.join(unique_tactics)}"
                
                # Elevate severity significantly
                new_severity = min(10.0, severity + (len(unique_tactics) * 1.5))
                event['severity'] = new_severity
                event['confidence'] = min(100, event.get('confidence', 0) + 20)
                event['action_taken'] = "Correlated & Escalated"

        return event

    def cleanup_stale(self):
        """Periodically clean memory for inactive IPs."""
        now = time.time()
        with self._lock:
            stale_ips = []
            for ip, events in self.history.items():
                active_events = [e for e in events if now - e['ts'] <= self.window]
                if not active_events:
                    stale_ips.append(ip)
                else:
                    self.history[ip] = active_events
                    
            for ip in stale_ips:
                del self.history[ip]

correlation_engine = CorrelationEngine()
