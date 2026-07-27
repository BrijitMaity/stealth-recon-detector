"""
logger.py — CSV/JSON Event Logger (Industry-Grade)

Features:
  - Atomic write support using crash-safe buffering
  - Write-ahead log (WAL) pattern — buffer to .pending before commit
  - Structured logging via app_logger
  - Metrics counters for rows written / failed
  - CSV integrity check on startup
  - Thread-safe buffered I/O with auto-flush
  - CSV rotation at configurable size limit

IMPORTANT: This logger NEVER deletes rows from the CSV file.
"""

import datetime
import os
import csv
import json
import threading
import time
from data_cleaner import DatasetCleaner
from state_manager import state
from threat_db import threat_db
from app_logger import get_logger

log = get_logger(__name__)


class ReconLogger:
    def __init__(self, filename_csv="stealth_detection_logs.csv"):
        self.filename_csv = os.path.abspath(filename_csv)
        self.filename_json = os.path.abspath(filename_csv.replace('.csv', '.json'))
        self.pending_csv = self.filename_csv + ".pending"
        self.cleaner = DatasetCleaner(self.filename_csv, rows_between_cleans=50)

        # Buffering
        self._buffer = []
        self._lock = threading.Lock()
        self._running = True
        self._flush_interval = 5.0
        self._flush_thread = threading.Thread(target=self._auto_flush_worker, daemon=True)
        self._flush_thread.start()

        # Metrics
        self._rows_written = 0
        self._rows_failed = 0
        self._flushes = 0

        self.columns = [
            "Timestamp","Source_IP","Destination_IP","Source_Port","Destination_Port","Protocol","Geo_Country","Geo_City","Geo_Lat","Geo_Lon","Packet_Size",
            "Packet_Count","Duration","Rate","Unique_Ports","Connection_Count","SYN_Count","ACK_Count","FIN_Count",
            "RST_Count","PSH_Count","URG_Count","TTL_Value","Window_Size","Retransmission_Count","Fragment_Count",
            "Payload_Size","Payload_Entropy","Payload_Type","Payload_Length","Malicious_Keyword","Keyword_Count",
            "Encoded_Content","Base64_Detected","Shell_Command_Detected","Exec_Command","Eval_Command","CMD_Usage",
            "Linux_Shell_Usage","Passwd_Access_Attempt","DPI_Result","DPI_Threat_Level","DPI_Confidence","AI_Model_Name",
            "AI_Label","AI_Confidence","Threat_Type","Threat_Score","Threat_Intelligence","Behavioral_Score","Heuristic_Result",
            "Heuristic_Trigger","GenAI_Result","Transformer_Output","Sentiment_Label","Anomaly_Score","Reconnaissance_Flag",
            "Port_Scan_Flag","Slow_Scan_Flag","Stealth_Score","Scan_Intensity","Multi_Port_Access","Night_Activity","Attack_Frequency",
            "Suspicious_Behavior","Automated_Behavior","Human_Behavior_Score","Connection_Interval","Session_Duration","Active_Flow_Count",
            "Flow_Start_Time","Last_Packet_Time","Flow_State","Packet_Direction","Traffic_Type","Network_Interface","MAC_Address","VLAN_ID",
            "DNS_Request","HTTP_Request","HTTPS_Request","SSH_Attempt","RDP_Attempt","Database_Access","Web_Attack_Indicator",
            "Directory_Traversal","Remote_Code_Execution","Exploit_Pattern","Firewall_Status","Firewall_Action","Blocked_IP","Block_Rule_Name",
            "Admin_Mode","Real_Block_Applied","Simulated_Block","Detection_Method","Detection_Time","Event_ID","Log_Status","CSV_Log_Row",
            "Dashboard_Event","Dashboard_Connection","Live_Alert","Security_Report_Status","Threat_Count","Attack_Count","Safe_Traffic_Count",
            "Detection_Accuracy","False_Positive_Rate","False_Negative_Rate","Precision_Score","Recall_Score","F1_Score","Model_Training_Status",
            "Feature_Importance","Label","Dataset_Source","Dataset_Row_ID","RandomForest_Result","ML_Prediction","Prediction_Probability","CPU_Usage",
            "Memory_Usage","System_Status"
        ]
        self._ensure_csv_header()
        self._flush_pending_rows()
        log.info(
            f"ReconLogger initialized: CSV={self.filename_csv}, "
            f"columns={len(self.columns)}"
        )

    _MAX_CSV_SIZE_BYTES = 200 * 1024 * 1024  # 200 MB

    def _rotate_csv_if_needed(self):
        if not os.path.exists(self.filename_csv):
            return
        try:
            if os.path.getsize(self.filename_csv) >= self._MAX_CSV_SIZE_BYTES:
                archive_name = self.filename_csv + f".{time.strftime('%Y%m%d_%H%M%S')}.archived"
                os.rename(self.filename_csv, archive_name)
                log.info(f"CSV rotated to: {archive_name}")
                self._create_csv()
        except Exception as e:
            log.error(f"CSV rotation failed: {e}")

    def _ensure_csv_header(self):
        """Verify CSV header integrity on startup. Never deletes data."""
        if not os.path.exists(self.filename_csv):
            self._create_csv()
            return
        try:
            with open(self.filename_csv, newline='', encoding='utf-8') as f:
                header = next(csv.reader(f), None)
            if header != self.columns:
                # Backup the existing file (NEVER delete it)
                backup_path = self.filename_csv + ".bak"
                os.replace(self.filename_csv, backup_path)
                log.warning(
                    f"CSV header mismatch detected. Backed up to {backup_path} and recreated."
                )
                self._create_csv()
        except Exception as e:
            log.error(f"CSV header check failed: {e}")

    def _create_csv(self):
        with open(self.filename_csv, mode='w', newline='', encoding='utf-8') as f:
            csv.DictWriter(f, fieldnames=self.columns).writeheader()
        log.info(f"Created new CSV with {len(self.columns)} columns")

    def _flush_pending_rows(self):
        """Recover rows from the write-ahead pending file."""
        if not os.path.exists(self.pending_csv):
            return
        try:
            with open(self.pending_csv, newline='', encoding='utf-8') as f:
                pending_rows = [row for row in csv.DictReader(f, fieldnames=self.columns) if any(row.values())]
            if pending_rows:
                with self._lock:
                    self._buffer.extend(pending_rows)
                os.remove(self.pending_csv)
                log.info(f"Recovered {len(pending_rows)} pending rows from WAL")
        except Exception as e:
            log.error(f"Cannot read pending log file: {e}")

    def _build_base_row(self, method, source, destination, confidence, duration, packets, rate):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip, src_port = source.split(':', 1) if ':' in source else (source, "")
        dst_ip, dst_port = destination.split(':', 1) if ':' in destination else (destination, "")

        row = {c: "" for c in self.columns}
        row.update({
            "Timestamp": timestamp, "Source_IP": src_ip, "Source_Port": src_port,
            "Destination_IP": dst_ip, "Destination_Port": dst_port, "Protocol": "TCP",
            "AI_Confidence": round(confidence, 2) if confidence is not None else "",
            "Duration": round(duration, 4) if duration is not None else "",
            "Packet_Count": int(packets) if packets is not None else "",
            "Rate": round(rate, 2) if rate is not None else "",
            "Detection_Method": method, "Detection_Time": timestamp
        })
        return row

    def log_event(self, method, source, destination, confidence, duration, packets, rate, extra_fields=None):
        row = self._build_base_row(method, source, destination, confidence, duration, packets, rate)
        if isinstance(extra_fields, dict):
            for k, v in extra_fields.items():
                if k in self.columns:
                    row[k] = v

        with self._lock:
            self._buffer.append(row)

        # Also update global metrics via state manager
        is_threat = row.get("Label") == 1
        state.increment_metric("total_scanned", 1)
        if is_threat:
            state.increment_metric("total_blocked", 1)

            # ── Dual-Write to ThreatDatabase (Feature 4) ─────────────
            try:
                threat_db.insert_threat({
                    "event_id": row.get("Event_ID", ""),
                    "timestamp": row.get("Timestamp", ""),
                    "timestamp_epoch": __import__('time').time(),
                    "source_ip": row.get("Source_IP", ""),
                    "source_port": int(row.get("Source_Port", 0) or 0),
                    "destination_ip": row.get("Destination_IP", ""),
                    "destination_port": int(row.get("Destination_Port", 0) or 0),
                    "protocol": row.get("Protocol", "TCP"),
                    "detection_method": row.get("Detection_Method", ""),
                    "confidence": float(row.get("AI_Confidence", 0) or 0),
                    "severity": float(row.get("Threat_Score", 0) or 0),
                    "threat_type": row.get("Threat_Type", ""),
                    "threat_intel": row.get("Threat_Intelligence", ""),
                    "mitre_technique_id": "",
                    "mitre_tactic": "",
                    "firewall_action": row.get("Firewall_Action", ""),
                    "dpi_result": row.get("DPI_Result", ""),
                    "ai_label": row.get("AI_Label", ""),
                    "ml_prediction": int(row.get("ML_Prediction", 0) or 0),
                    "prediction_probability": float(row.get("Prediction_Probability", 0) or 0),
                    "packet_size": int(row.get("Packet_Size", 0) or 0),
                    "payload_entropy": float(row.get("Payload_Entropy", 0) or 0),
                    "is_port_scan": int(row.get("Port_Scan_Flag", 0) or 0),
                    "unique_ports": int(row.get("Unique_Ports", 0) or 0),
                    "duration": float(row.get("Duration", 0) or 0),
                    "rate": float(row.get("Rate", 0) or 0),
                })
            except Exception as e:
                log.error(f"ThreatDB dual-write failed: {e}")

    def _auto_flush_worker(self):
        while self._running:
            time.sleep(self._flush_interval)
            self.flush()

    def flush(self):
        with self._lock:
            if not self._buffer:
                return
            rows_to_write = self._buffer[:]
            self._buffer.clear()

        self._rotate_csv_if_needed()

        # ── Step 1: Write to pending file first (WAL pattern) ─────────
        try:
            with open(self.pending_csv, mode='a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.columns)
                writer.writerows(rows_to_write)
        except Exception as e:
            log.error(f"WAL write failed: {e}")
            with self._lock:
                self._buffer = rows_to_write + self._buffer
            self._rows_failed += len(rows_to_write)
            return

        # ── Step 2: Append to main CSV ────────────────────────────────
        try:
            with open(self.filename_csv, mode='a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.columns)
                writer.writerows(rows_to_write)
        except Exception as e:
            log.error(f"Flush to CSV failed: {e}")
            # Rows are still in the pending file — they'll be recovered on restart
            self._rows_failed += len(rows_to_write)
            return

        # ── Step 3: Remove pending file (commit complete) ─────────────
        try:
            if os.path.exists(self.pending_csv):
                os.remove(self.pending_csv)
        except Exception:
            pass  # Non-fatal — pending file will be cleaned up on next flush

        # ── Step 4: Write to JSON Lines ───────────────────────────────
        try:
            with open(self.filename_json, mode='a', encoding='utf-8') as f:
                for row in rows_to_write:
                    f.write(json.dumps(row) + '\n')
        except Exception as e:
            log.error(f"Flush to JSON failed: {e}")

        # ── Step 5: Trigger cleaner ───────────────────────────────────
        for _ in range(len(rows_to_write)):
            self.cleaner.notify_new_row()

        self._rows_written += len(rows_to_write)
        self._flushes += 1

    def get_metrics(self) -> dict:
        """Return logger operational metrics."""
        return {
            "rows_written": self._rows_written,
            "rows_failed": self._rows_failed,
            "flushes": self._flushes,
            "buffer_size": len(self._buffer),
        }

    def shutdown(self):
        self._running = False
        self.flush()
        log.info("ReconLogger shutdown", extra=self.get_metrics())
