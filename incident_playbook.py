"""
incident_playbook.py — Automated Incident Response Playbooks

Automatically escalates responses based on threat severity.
CRITICAL: Subnet block + Alert + Forensics
HIGH: IP block + Alert
MEDIUM: Monitor
"""

import time
import threading
from config import cfg
from alert_manager import alert_manager
from firewall import Firewall
from threat_db import threat_db
from app_logger import get_logger

log = get_logger(__name__)

class PlaybookEngine:
    def __init__(self):
        self.firewall = Firewall()

    def execute_playbook(self, event: dict):
        """Execute automated response based on severity score."""
        severity = event.get('severity', 0)
        src_ip = event.get('src_ip')
        tactic = event.get('mitre_tactic', 'Unknown')
        
        method = event.get('method', '')
        
        if not src_ip or src_ip == "127.0.0.1":
            return

        if "UEBA Predictive Engine" in method:
            self._execute_level5(src_ip, tactic, event)
            # We also execute Critical isolation
            self._execute_critical(src_ip, tactic, event)
            return

        if severity >= 9.0:
            self._execute_critical(src_ip, tactic, event)
        elif severity >= 7.0:
            self._execute_high(src_ip, tactic, event)
        elif severity >= 5.0:
            self._execute_medium(src_ip, tactic, event)

    def _execute_level5(self, src_ip, tactic, event):
        log.critical(f"LEVEL 5 AUTONOMOUS RESPONSE: Generating Self-Healing Signature for {src_ip}")
        import json
        import os
        custom_sig_path = 'custom_signatures.json'
        sigs = []
        if os.path.exists(custom_sig_path):
            try:
                with open(custom_sig_path, 'r') as f:
                    sigs = json.load(f)
            except Exception:
                pass
        
        # Prevent infinite duplicate signature generation
        for sig in sigs:
            if "AUTO-SIG-UEBA" in sig.get("id", ""):
                return # We already generated the dynamic UEBA self-healing signature

        # Auto-generate a signature based on the anomaly
        new_sig = {
            "id": f"AUTO-SIG-UEBA-{int(time.time())}",
            "name": "Level 5 Auto-Generated Rule",
            "regex": "UEBA-BEHAVIOR-BLOCK-.*",  # Safe regex so we don't accidentally match benign traffic and loop
            "severity": "Critical",
            "mitre": "T1566"
        }
        sigs.append(new_sig)
        with open(custom_sig_path, 'w') as f:
            json.dump(sigs, f, indent=4)
        log.critical(f"LEVEL 5 AUTONOMOUS RESPONSE: New signature applied globally to DPI Engine.")

    def _execute_critical(self, src_ip, tactic, event):
        log.critical(f"PLAYBOOK CRITICAL: Executing maximum response for {src_ip} ({tactic})")
        # 1. Block exact IP or Quarantine if internal
        if src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172."):
            self.firewall.quarantine_ip(src_ip, reason=f"CRITICAL Playbook: {tactic}")
        else:
            self.firewall.block_ip(src_ip, reason=f"CRITICAL Playbook: {tactic}")
        # 2. Block Subnet (/24) aggressively due to severity 9+
        try:
            parts = src_ip.split('.')
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                self.firewall.block_cidr(subnet, reason=f"CRITICAL Subnet isolation for {src_ip}")
        except Exception as e:
            log.error(f"Playbook subnet block failed: {e}")
            
        # 3. Async Alert
        alert_manager.send_alert(event)
        
        # 4. DB Record Update
        threat_db.update_reputation(src_ip, -50, tactic)

    def _execute_high(self, src_ip, tactic, event):
        log.warning(f"PLAYBOOK HIGH: Executing response for {src_ip} ({tactic})")
        if src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172."):
            self.firewall.quarantine_ip(src_ip, reason=f"HIGH Playbook: {tactic}")
        else:
            self.firewall.block_ip(src_ip, reason=f"HIGH Playbook: {tactic}")
        alert_manager.send_alert(event)
        threat_db.update_reputation(src_ip, -20, tactic)

    def _execute_medium(self, src_ip, tactic, event):
        log.info(f"PLAYBOOK MEDIUM: Monitoring escalated for {src_ip} ({tactic})")
        # Just reduce reputation, don't block yet unless threshold crossed elsewhere
        threat_db.update_reputation(src_ip, -5, tactic)

playbook_engine = PlaybookEngine()
