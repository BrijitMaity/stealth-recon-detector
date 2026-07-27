"""
alert_manager.py — Real-Time Alerting System (Industry-Grade)

Features:
  - Slack webhook integration (instant SOC alerts)
  - SMTP email integration (for compliance & audit trails)
  - Generic webhook support (PagerDuty, Opsgenie, custom SIEM)
  - Severity-based routing: only HIGH/CRITICAL threats trigger alerts
  - De-duplication: rate-limits alerts per-IP to prevent alert storms
  - Async dispatch via background threads (non-blocking)
  - Structured JSON payloads with MITRE ATT&CK context
  - Graceful degradation: logs errors but never crashes the monitor

Usage:
    from alert_manager import alert_manager
    alert_manager.send_alert(event_data)  # Non-blocking
"""

import time
import json
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from config import cfg
from app_logger import get_logger

log = get_logger(__name__)

# Optional: requests for HTTP webhooks
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
    log.warning("'requests' not installed. Webhook/Slack alerts disabled.")


class AlertManager:
    """
    Multi-channel alerting engine with per-IP cooldown and severity gating.
    
    Alert Channels:
      1. Slack Webhook   — set STEALTH_SLACK_WEBHOOK env var
      2. SMTP Email      — set STEALTH_SMTP_HOST, STEALTH_SMTP_FROM, STEALTH_SMTP_TO
      3. Generic Webhook — set STEALTH_WEBHOOK_URL (POST JSON payload)
    """

    def __init__(self):
        self._cooldown_map = defaultdict(float)  # ip -> last_alert_timestamp
        self._lock = threading.Lock()
        self._alert_count = 0
        self._suppressed_count = 0
        self._failed_count = 0

        # Detect active channels
        self._channels = []
        if cfg.SLACK_WEBHOOK_URL:
            self._channels.append("slack")
        if cfg.SMTP_HOST and cfg.SMTP_FROM and cfg.SMTP_TO:
            self._channels.append("email")
        if cfg.WEBHOOK_URL:
            self._channels.append("webhook")

        if self._channels:
            log.info(f"AlertManager initialized with channels: {', '.join(self._channels)}")
            self.mock_mode = False
        else:
            log.warning("AlertManager initialized with NO channels configured. Running in MOCK MODE.")
            self.mock_mode = True

    def send_alert(self, event_data: dict):
        """
        Dispatch an alert for a threat event (non-blocking).
        
        Args:
            event_data: dict with keys like:
                - source_ip, destination_ip, method, confidence,
                  severity, intel, mitre_technique, mitre_tactic, event_id, timestamp
        """
        severity = float(event_data.get("severity", 0))
        source_ip = event_data.get("source_ip", "unknown")

        # Gate 1: Severity threshold
        if severity < cfg.ALERT_SEVERITY_THRESHOLD:
            return

        # Gate 2: Per-IP cooldown (prevent alert storms)
        now = time.time()
        with self._lock:
            last_alert = self._cooldown_map.get(source_ip, 0)
            if now - last_alert < cfg.ALERT_COOLDOWN_SECONDS:
                self._suppressed_count += 1
                return
            self._cooldown_map[source_ip] = now

            # Memory protection: limit cooldown map size
            if len(self._cooldown_map) > 10000:
                # Remove oldest entries
                oldest_ips = sorted(self._cooldown_map, key=self._cooldown_map.get)[:5000]
                for ip in oldest_ips:
                    del self._cooldown_map[ip]

        # Dispatch asynchronously
        threading.Thread(
            target=self._dispatch_all_channels,
            args=(event_data,),
            daemon=True
        ).start()

    def _dispatch_all_channels(self, event_data: dict):
        """Send alert to all configured channels."""
        self._alert_count += 1
        payload = self._build_payload(event_data)
        
        if self.mock_mode:
            log.warning(f"MOCK ALERT DISPATCHED: CRITICAL THREAT DETECTED - {payload['source_ip']} ({payload['severity_score']}) -> {payload.get('threat_intel', 'N/A')}")
            print(f"\n\033[91m[MOCK ALERT EMAIL SENT] -> Admin notified about {payload['source_ip']}\033[0m")
            return

        for channel in self._channels:
            try:
                if channel == "slack":
                    self._send_slack(payload)
                elif channel == "email":
                    self._send_email(payload, event_data)
                elif channel == "webhook":
                    self._send_webhook(payload)
            except Exception as e:
                self._failed_count += 1
                log.error(f"Alert dispatch failed ({channel}): {e}")

    def _build_payload(self, event_data: dict) -> dict:
        """Build a structured JSON alert payload."""
        severity = float(event_data.get("severity", 0))
        severity_label = "CRITICAL" if severity >= 9.0 else ("HIGH" if severity >= 7.0 else "MEDIUM")

        return {
            "alert_type": "stealth_recon_detection",
            "severity": severity_label,
            "severity_score": severity,
            "event_id": event_data.get("event_id", "N/A"),
            "timestamp": event_data.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
            "source_ip": event_data.get("source_ip", "N/A"),
            "destination_ip": event_data.get("destination_ip", "N/A"),
            "detection_method": event_data.get("method", "N/A"),
            "confidence": event_data.get("confidence", "N/A"),
            "threat_intel": event_data.get("intel", "N/A"),
            "mitre_attack": {
                "technique": event_data.get("mitre_technique", ""),
                "tactic": event_data.get("mitre_tactic", ""),
            },
            "firewall_action": event_data.get("firewall_status", "N/A"),
            "system_version": cfg.VERSION,
        }

    # ── Slack Channel ────────────────────────────────────────────────
    def _send_slack(self, payload: dict):
        """Send a rich Slack message via incoming webhook."""
        if not _REQUESTS_AVAILABLE:
            return

        severity = payload["severity"]
        color = "#e74c3c" if severity == "CRITICAL" else ("#f39c12" if severity == "HIGH" else "#3498db")
        emoji = "🚨" if severity == "CRITICAL" else "⚠️"

        slack_payload = {
            "text": f"{emoji} *{severity} Threat Detected* — AI Stealth Recon SOC",
            "attachments": [{
                "color": color,
                "fields": [
                    {"title": "Source IP", "value": payload["source_ip"], "short": True},
                    {"title": "Method", "value": payload["detection_method"], "short": True},
                    {"title": "Confidence", "value": f"{payload['confidence']}%", "short": True},
                    {"title": "MITRE ATT&CK", "value": f"{payload['mitre_attack']['technique']} ({payload['mitre_attack']['tactic']})", "short": True},
                    {"title": "Threat Intel", "value": str(payload["threat_intel"])[:200], "short": False},
                    {"title": "Firewall", "value": payload["firewall_action"], "short": True},
                    {"title": "Event ID", "value": payload["event_id"], "short": True},
                ],
                "footer": f"AI Stealth Recon SOC v{cfg.VERSION}",
                "ts": int(time.time()),
            }]
        }

        resp = requests.post(
            cfg.SLACK_WEBHOOK_URL,
            json=slack_payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Slack returned HTTP {resp.status_code}: {resp.text}")
        log.info(f"Slack alert sent for {payload['source_ip']} (severity={severity})")

    # ── Email Channel ────────────────────────────────────────────────
    def _send_email(self, payload: dict, event_data: dict):
        """Send an alert email via SMTP."""
        severity = payload["severity"]
        subject = f"[{severity}] Stealth Recon Alert — {payload['source_ip']} — {payload['detection_method']}"

        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: {'#e74c3c' if severity == 'CRITICAL' else '#f39c12'}">
                {'🚨' if severity == 'CRITICAL' else '⚠️'} {severity} Threat Detected
            </h2>
            <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse;">
                <tr><td><strong>Event ID</strong></td><td>{payload['event_id']}</td></tr>
                <tr><td><strong>Timestamp</strong></td><td>{payload['timestamp']}</td></tr>
                <tr><td><strong>Source IP</strong></td><td>{payload['source_ip']}</td></tr>
                <tr><td><strong>Destination</strong></td><td>{payload['destination_ip']}</td></tr>
                <tr><td><strong>Detection Method</strong></td><td>{payload['detection_method']}</td></tr>
                <tr><td><strong>Confidence</strong></td><td>{payload['confidence']}%</td></tr>
                <tr><td><strong>MITRE ATT&CK</strong></td><td>{payload['mitre_attack']['technique']} — {payload['mitre_attack']['tactic']}</td></tr>
                <tr><td><strong>Threat Intel</strong></td><td>{str(payload['threat_intel'])[:500]}</td></tr>
                <tr><td><strong>Firewall Action</strong></td><td>{payload['firewall_action']}</td></tr>
            </table>
            <br>
            <p style="color: #7f8c8d; font-size: 12px;">
                Generated by AI Stealth Recon SOC v{cfg.VERSION}
            </p>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.SMTP_FROM
        msg["To"] = cfg.SMTP_TO
        msg.attach(MIMEText(body_html, "html"))

        try:
            with smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=15) as server:
                server.ehlo()
                if cfg.SMTP_PORT in (587, 465):
                    server.starttls()
                if cfg.SMTP_USER and cfg.SMTP_PASS:
                    server.login(cfg.SMTP_USER, cfg.SMTP_PASS)
                server.sendmail(cfg.SMTP_FROM, cfg.SMTP_TO.split(","), msg.as_string())
            log.info(f"Email alert sent for {payload['source_ip']} to {cfg.SMTP_TO}")
        except Exception as e:
            raise RuntimeError(f"SMTP send failed: {e}")

    # ── Generic Webhook Channel ──────────────────────────────────────
    def _send_webhook(self, payload: dict):
        """POST JSON payload to a generic webhook URL (PagerDuty, Opsgenie, custom SIEM)."""
        if not _REQUESTS_AVAILABLE:
            return

        resp = requests.post(
            cfg.WEBHOOK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        if resp.status_code not in (200, 201, 202, 204):
            raise RuntimeError(f"Webhook returned HTTP {resp.status_code}: {resp.text}")
        log.info(f"Webhook alert sent for {payload['source_ip']}")

    # ── Metrics ──────────────────────────────────────────────────────
    def get_metrics(self) -> dict:
        """Return alert system operational metrics."""
        return {
            "total_alerts_sent": self._alert_count,
            "alerts_suppressed": self._suppressed_count,
            "alerts_failed": self._failed_count,
            "active_channels": self._channels,
            "cooldown_map_size": len(self._cooldown_map),
        }


# Singleton instance
alert_manager = AlertManager()


if __name__ == "__main__":
    # Test with a mock event
    test_event = {
        "event_id": "EVT-TEST-001",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": "10.0.0.50",
        "destination_ip": "127.0.0.1",
        "method": "DPI Security Rule",
        "confidence": 99.5,
        "severity": 9.8,
        "intel": "SQL Injection detected in HTTP payload",
        "mitre_technique": "T1190",
        "mitre_tactic": "Initial Access",
        "firewall_status": "Blocked",
    }
    alert_manager.send_alert(test_event)
    print(f"Alert metrics: {alert_manager.get_metrics()}")
    time.sleep(2)  # Wait for async dispatch
    print(f"Alert metrics after dispatch: {alert_manager.get_metrics()}")
