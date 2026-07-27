"""
dpi_analyzer.py — Deep Packet Inspection Engine (Industry-Grade)

Features:
  - 10 industry-standard regex signature rules
  - CWE/CVE references for each rule
  - YARA-style rule IDs
  - Payload size limit to prevent ReDoS
  - Signature versioning metadata
  - Base64 obfuscation detection and decoding
  - GenAI fallback for unknown patterns

Signature Database Version: 2.0
"""

# pyrefly: ignore [missing-import]
from scapy.all import Raw
import base64
import re

from app_logger import get_logger

log = get_logger(__name__)

# Maximum payload size to inspect (prevents ReDoS on huge payloads)
_MAX_PAYLOAD_INSPECT_BYTES = 65536  # 64KB
_SIGNATURE_DB_VERSION = "2.0"


class DPIAnalyzer:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.signature_version = _SIGNATURE_DB_VERSION
        self._match_count = 0  # Total signature matches for metrics

        # Industry-standard DPI regex rules with CWE/CVE references
        self.signatures = [
            {
                "id": "DPI-001",
                "name": "SQL Injection (SQLi)",
                "pattern": re.compile(r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table|1=1|1'1|WAITFOR\s+DELAY|--\s*$)"),
                "severity": "High",
                "confidence": 95.0,
                "cwe": "CWE-89",
                "references": ["CVE-2017-5638", "OWASP A03:2021"],
                "mitre_technique": "T1190",
            },
            {
                "id": "DPI-002",
                "name": "NoSQL Injection",
                "pattern": re.compile(r"(?i)(\{\$gt:|\{\$ne:|\{\$where:|db\.injection\()"),
                "severity": "High",
                "confidence": 90.0,
                "cwe": "CWE-943",
                "references": ["OWASP A03:2021"],
                "mitre_technique": "T1190",
            },
            {
                "id": "DPI-003",
                "name": "Cross-Site Scripting (XSS)",
                "pattern": re.compile(r"(?i)(<script>|javascript:|onerror=|onload=|document\.cookie|alert\()"),
                "severity": "Medium",
                "confidence": 90.0,
                "cwe": "CWE-79",
                "references": ["CVE-2020-11022", "OWASP A07:2021"],
                "mitre_technique": "T1059.007",
            },
            {
                "id": "DPI-004",
                "name": "Remote Code Execution (RCE)",
                "pattern": re.compile(r"(?i)(cmd\.exe|/bin/sh|/bin/bash|wget\s|curl\s|eval\(|system\(|powershell\.exe|powershell\s+-enc)"),
                "severity": "Critical",
                "confidence": 99.0,
                "cwe": "CWE-78",
                "references": ["CVE-2021-44228", "OWASP A03:2021"],
                "mitre_technique": "T1059",
            },
            {
                "id": "DPI-005",
                "name": "Directory Traversal / LFI",
                "pattern": re.compile(r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|/etc/passwd|boot\.ini|win\.ini|php://filter)"),
                "severity": "High",
                "confidence": 95.0,
                "cwe": "CWE-22",
                "references": ["CVE-2019-11510", "OWASP A01:2021"],
                "mitre_technique": "T1083",
            },
            {
                "id": "DPI-006",
                "name": "Command Injection",
                "pattern": re.compile(r"(?i)(&|\||\;|\`)\s*(whoami|id|ls|dir|cat|type|netstat|ipconfig)\b"),
                "severity": "Critical",
                "confidence": 98.0,
                "cwe": "CWE-77",
                "references": ["OWASP A03:2021"],
                "mitre_technique": "T1059",
            },
            {
                "id": "DPI-007",
                "name": "Log4j JNDI Exploitation",
                "pattern": re.compile(r"(?i)(\$\{jndi:(ldap|rmi|ldaps|dns)://)"),
                "severity": "Critical",
                "confidence": 99.0,
                "cwe": "CWE-917",
                "references": ["CVE-2021-44228", "CVE-2021-45046"],
                "mitre_technique": "T1190",
            },
            {
                "id": "DPI-008",
                "name": "Server-Side Request Forgery (SSRF)",
                "pattern": re.compile(r"(?i)(169\.254\.169\.254|file://|gopher://|dict://)"),
                "severity": "High",
                "confidence": 92.0,
                "cwe": "CWE-918",
                "references": ["CVE-2019-5418", "OWASP A10:2021"],
                "mitre_technique": "T1190",
            },
            {
                "id": "DPI-009",
                "name": "XML External Entity (XXE)",
                "pattern": re.compile(r"(?i)(<!ENTITY\s+[^>]+SYSTEM\s+[\"'](file|http|https)://)"),
                "severity": "High",
                "confidence": 95.0,
                "cwe": "CWE-611",
                "references": ["CVE-2018-11776", "OWASP A05:2021"],
                "mitre_technique": "T1190",
            },
            {
                "id": "DPI-010",
                "name": "PHP Code Injection / Obfuscation",
                "pattern": re.compile(r"(?i)(eval\s*\(\s*base64_decode|assert\s*\(|preg_replace\s*\(\s*'.*e'|gzinflate|str_rot13)"),
                "severity": "Critical",
                "confidence": 95.0,
                "cwe": "CWE-94",
                "references": ["OWASP A03:2021"],
                "mitre_technique": "T1059.001",
            }
        ]
        
        # Load custom signatures from file
        import os, json
        custom_sig_path = 'custom_signatures.json'
        if os.path.exists(custom_sig_path):
            try:
                with open(custom_sig_path, 'r') as f:
                    custom_sigs = json.load(f)
                    for sig in custom_sigs:
                        self.signatures.append({
                            "id": sig["id"],
                            "name": sig["name"],
                            "pattern": re.compile(sig.get("pattern", sig.get("regex"))),
                            "severity": sig["severity"],
                            "confidence": 100.0,
                            "cwe": sig.get("cwe", "Custom"),
                            "references": ["User Defined"],
                            "mitre_technique": "Custom"
                        })
            except Exception as e:
                log.error(f"Error loading custom signatures: {e}")
                
        log.info(
            f"DPI engine initialized with {len(self.signatures)} signatures "
            f"(DB v{self.signature_version})"
        )

    def get_signature_count(self) -> int:
        """Return the number of loaded signatures."""
        return len(self.signatures)

    def get_signatures(self) -> list:
        """Return a simplified list of loaded signatures for the frontend UI."""
        return [
            {
                "id": sig["id"],
                "name": sig["name"],
                "severity": sig["severity"],
                "cwe": sig["cwe"]
            }
            for sig in self.signatures
        ]

    def get_match_count(self) -> int:
        """Return total number of signature matches since startup."""
        return self._match_count

    def inspect_payload(self, packet):
        """Inspects the payload of a packet for malicious content.

        Returns a dict with threat details if malicious, or {"is_threat": False}.
        Enforces a payload size limit to prevent regex denial-of-service.
        """
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                # Enforce payload size limit to prevent ReDoS
                if len(payload) > _MAX_PAYLOAD_INSPECT_BYTES:
                    log.debug(f"Payload truncated from {len(payload)} to {_MAX_PAYLOAD_INSPECT_BYTES} bytes for DPI")
                    payload = payload[:_MAX_PAYLOAD_INSPECT_BYTES]

                # Decode to string
                text_payload = payload.decode('utf-8', errors='ignore')
                base64_detected = False

                # Attempt to decode Base64 obfuscated payloads
                # Match typical base64 strings (at least 16 chars to reduce false positives)
                if len(text_payload.strip()) >= 16 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', text_payload.strip()):
                    try:
                        decoded_bytes = base64.b64decode(text_payload.strip(), validate=True)
                        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                        # If decoded text has letters and looks somewhat like a string
                        if any(c.isalpha() for c in decoded_text):
                            text_payload = decoded_text
                            base64_detected = True
                    except Exception:
                        pass

                # Industry-level Regex Signature checking
                for sig in self.signatures:
                    if sig["pattern"].search(text_payload):
                        self._match_count += 1
                        log.info(
                            f"DPI match: {sig['id']} ({sig['name']})",
                            extra={
                                "rule_id": sig["id"],
                                "severity": sig["severity"],
                                "cwe": sig["cwe"],
                            }
                        )
                        return {
                            "is_threat": True,
                            "reason": f"DPI matched signature for {sig['name']}" + (" (Base64 Encoded)" if base64_detected else ""),
                            "payload_snippet": text_payload[:50],
                            "severity": sig["severity"],
                            "confidence": sig["confidence"],
                            "base64_detected": base64_detected,
                            "rule_id": sig["id"],
                            "cwe": sig["cwe"],
                            "mitre_technique": sig["mitre_technique"],
                            "references": sig.get("references", []),
                        }

                # GenAI Analysis for complex payloads
                if len(text_payload) > 10:
                    behavior_summary = f"Payload content detected: {text_payload[:100]}"
                    analysis = self.analyzer.analyze_behavior(behavior_summary)
                    if analysis["is_threat"]:
                        return {
                            "is_threat": True,
                            "reason": "GenAI identified malicious payload intent" + (" (Base64 Encoded)" if base64_detected else ""),
                            "payload_snippet": text_payload[:50],
                            "severity": "High",  # Defaulting GenAI severity to High
                            "confidence": analysis.get("confidence", 85.0),
                            "base64_detected": base64_detected,
                            "rule_id": "DPI-AI",
                            "cwe": "N/A",
                            "mitre_technique": analysis.get("mitre", {}).get("technique_id", "T1595"),
                            "references": [],
                        }
            except Exception as e:
                # Log the error instead of silently discarding it
                log.error(f"Payload inspection error from {packet.summary()}: {e}")
        return {"is_threat": False}
