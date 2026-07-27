"""
threat_db.py — Threat Event Database (Industry-Grade, ORM)

Dedicated database for threat event storage and querying.
Refactored to use SQLAlchemy ORM to enable seamless scaling
to PostgreSQL, MySQL, or Elasticsearch.
"""

import threading
import time
import datetime
import json
import os
import csv
from collections import deque
from sqlalchemy import create_engine, func, desc, exc
from sqlalchemy.orm import sessionmaker

from config import cfg
from app_logger import get_logger
from models import Base, ThreatEvent, IPReputation, AlertHistory, PerformanceMetrics

log = get_logger(__name__)

class ThreatDatabase:
    """
    High-performance threat event database using SQLAlchemy ORM.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or cfg.THREAT_DB_PATH
        # Setup SQLAlchemy Engine
        # Setup SQLAlchemy Engine
        db_url = f"sqlite:///{self.db_path}"
        # For sqlite, we need check_same_thread=False since we use multiple threads
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False, "timeout": 15})
        
        from sqlalchemy import text
        with self.engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL;"))
        
        self.Session = sessionmaker(bind=self.engine)
        
        self._buffer = deque(maxlen=10000)
        self._buffer_lock = threading.Lock()
        self._running = True

        # Metrics
        self._inserts = 0
        self._queries = 0
        self._purged = 0

        self._init_db()

        # Background flush thread
        self._flush_thread = threading.Thread(target=self._auto_flush, daemon=True)
        self._flush_thread.start()

        # Background retention thread
        self._retention_thread = threading.Thread(target=self._retention_worker, daemon=True)
        self._retention_thread.start()

        log.info(f"ThreatDatabase (ORM) initialized: {db_url}")

    def _init_db(self):
        """Create all tables defined in models."""
        Base.metadata.create_all(self.engine)
        log.info("ThreatDatabase schema initialized via SQLAlchemy")

    def insert_threat(self, event: dict):
        """Buffer a threat event for bulk insertion."""
        with self._buffer_lock:
            self._buffer.append(event)

    def _flush_buffer(self):
        """Flush buffered events to the database."""
        with self._buffer_lock:
            if not self._buffer:
                return
            events = list(self._buffer)
            self._buffer.clear()

        session = self.Session()
        try:
            threat_mappings = []
            ip_rep_updates = {} # track ip -> reputation data
            
            for event in events:
                now_str = event.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                now_dt = datetime.datetime.strptime(now_str, "%Y-%m-%d %H:%M:%S") if now_str else datetime.datetime.now()
                now_epoch = event.get("timestamp_epoch", time.time())
                
                threat_mappings.append({
                    "event_id": event.get("event_id", ""),
                    "timestamp": now_dt,
                    "timestamp_epoch": now_epoch,
                    "source_ip": event.get("source_ip", ""),
                    "source_port": event.get("source_port", 0),
                    "destination_ip": event.get("destination_ip", ""),
                    "destination_port": event.get("destination_port", 0),
                    "protocol": event.get("protocol", "TCP"),
                    "detection_method": event.get("detection_method", ""),
                    "confidence": event.get("confidence", 0.0),
                    "severity": event.get("severity", 0.0),
                    "threat_type": event.get("threat_type", ""),
                    "threat_intel": event.get("threat_intel", ""),
                    "mitre_technique_id": event.get("mitre_technique_id", ""),
                    "mitre_tactic": event.get("mitre_tactic", ""),
                    "firewall_action": event.get("firewall_action", ""),
                    "dpi_result": event.get("dpi_result", ""),
                    "ai_label": event.get("ai_label", ""),
                    "ml_prediction": event.get("ml_prediction", 0),
                    "prediction_probability": event.get("prediction_probability", 0.0),
                    "packet_size": event.get("packet_size", 0),
                    "payload_entropy": event.get("payload_entropy", 0.0),
                    "is_port_scan": bool(event.get("is_port_scan", 0)),
                    "unique_ports": event.get("unique_ports", 0),
                    "duration": event.get("duration", 0.0),
                    "rate": event.get("rate", 0.0),
                    "raw_event_json": json.dumps(event, default=str)
                })

                src_ip = event.get("source_ip", "")
                if src_ip:
                    if src_ip not in ip_rep_updates:
                        ip_rep_updates[src_ip] = []
                    ip_rep_updates[src_ip].append({
                        "timestamp": now_dt,
                        "confidence": event.get("confidence", 0.0),
                        "severity": event.get("severity", 0.0)
                    })
            
            # Bulk insert threats
            if threat_mappings:
                session.bulk_insert_mappings(ThreatEvent, threat_mappings)
                self._inserts += len(threat_mappings)

            # Process IP Reputation Upserts
            for ip, updates in ip_rep_updates.items():
                rep = session.query(IPReputation).filter_by(ip=ip).first()
                latest_dt = max([u["timestamp"] for u in updates])
                max_sev = max([u["severity"] for u in updates])
                sum_conf = sum([u["confidence"] for u in updates])
                count = len(updates)

                if rep:
                    rep.last_seen = max(rep.last_seen, latest_dt) if rep.last_seen else latest_dt
                    rep.total_events += count
                    rep.total_threats += count
                    rep.avg_confidence = ((rep.avg_confidence * (rep.total_events - count)) + sum_conf) / rep.total_events
                    if max_sev > rep.max_severity:
                        rep.max_severity = max_sev
                else:
                    new_rep = IPReputation(
                        ip=ip,
                        first_seen=latest_dt,
                        last_seen=latest_dt,
                        total_events=count,
                        total_threats=count,
                        avg_confidence=sum_conf / count,
                        max_severity=max_sev
                    )
                    session.add(new_rep)

            session.commit()
        except Exception as e:
            session.rollback()
            log.error(f"ThreatDB ORM insert error: {e}")
        finally:
            session.close()

    def _auto_flush(self):
        """Background thread to flush buffer every 3 seconds."""
        while self._running:
            time.sleep(3)
            try:
                self._flush_buffer()
            except Exception as e:
                log.error(f"ThreatDB auto-flush error: {e}")

    def query_threats(self, start_time: str = None, end_time: str = None,
                      source_ip: str = None, severity_min: float = None,
                      detection_method: str = None, limit: int = 100) -> list:
        """Query threat events with filters."""
        self._queries += 1
        session = self.Session()
        try:
            query = session.query(ThreatEvent)
            
            if start_time:
                query = query.filter(ThreatEvent.timestamp >= datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S"))
            if end_time:
                query = query.filter(ThreatEvent.timestamp <= datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S"))
            if source_ip:
                query = query.filter(ThreatEvent.source_ip == source_ip)
            if severity_min is not None:
                query = query.filter(ThreatEvent.severity >= severity_min)
            if detection_method:
                query = query.filter(ThreatEvent.detection_method.like(f"%{detection_method}%"))
                
            results = query.order_by(desc(ThreatEvent.timestamp_epoch)).limit(limit).all()
            
            # Convert objects to dicts to maintain API compatibility
            out = []
            for r in results:
                d = r.__dict__.copy()
                d.pop('_sa_instance_state', None)
                if isinstance(d.get("timestamp"), datetime.datetime):
                    d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                out.append(d)
            return out
        finally:
            session.close()

    def get_ip_reputation(self, ip_address: str = None, limit: int = 50) -> list:
        """Get IP reputation data."""
        self._queries += 1
        session = self.Session()
        try:
            if ip_address:
                results = session.query(IPReputation).filter(IPReputation.ip == ip_address).all()
            else:
                results = session.query(IPReputation).order_by(desc(IPReputation.total_threats)).limit(limit).all()
                
            out = []
            for r in results:
                d = r.__dict__.copy()
                d.pop('_sa_instance_state', None)
                if isinstance(d.get("first_seen"), datetime.datetime):
                    d["first_seen"] = d["first_seen"].strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(d.get("last_seen"), datetime.datetime):
                    d["last_seen"] = d["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
                out.append(d)
            return out
        finally:
            session.close()

    def update_reputation(self, ip_address: str, score_delta: float, tactic: str = ""):
        """Manually adjust IP reputation score."""
        now = datetime.datetime.now()
        session = self.Session()
        try:
            rep = session.query(IPReputation).filter_by(ip=ip_address).first()
            if rep:
                rep.last_seen = now
                rep.osint_score += score_delta
            else:
                new_rep = IPReputation(
                    ip=ip_address,
                    first_seen=now,
                    last_seen=now,
                    osint_score=score_delta,
                    tags=f'["{tactic}"]' if tactic else '[]'
                )
                session.add(new_rep)
            session.commit()
        except Exception as e:
            session.rollback()
            log.error(f"Failed to update reputation for {ip_address}: {e}")
        finally:
            session.close()

    def get_threat_stats(self) -> dict:
        """Get aggregated threat statistics."""
        self._queries += 1
        session = self.Session()
        try:
            total = session.query(ThreatEvent).count()
            high_sev = session.query(ThreatEvent).filter(ThreatEvent.severity >= 7.0).count()
            critical = session.query(ThreatEvent).filter(ThreatEvent.severity >= 9.0).count()
            unique_ips = session.query(ThreatEvent.source_ip).distinct().count()

            methods = {}
            for meth, cnt in session.query(ThreatEvent.detection_method, func.count(ThreatEvent.id)).group_by(ThreatEvent.detection_method).all():
                methods[meth] = cnt

            twenty_four_ago = time.time() - 86400
            hourly = {}
            for row in session.query(ThreatEvent).filter(ThreatEvent.timestamp_epoch > twenty_four_ago).all():
                if not row.timestamp:
                    continue
                hour = row.timestamp.strftime("%H")
                hourly[hour] = hourly.get(hour, 0) + 1

            return {
                "total_threats": total,
                "high_severity": high_sev,
                "critical_severity": critical,
                "unique_source_ips": unique_ips,
                "method_distribution": methods,
                "hourly_trend_24h": hourly,
            }
        finally:
            session.close()

    def _retention_worker(self):
        """Background thread to purge old data."""
        while self._running:
            time.sleep(3600)
            try:
                cutoff = datetime.datetime.now() - datetime.timedelta(days=cfg.THREAT_RETENTION_DAYS)
                session = self.Session()
                deleted = session.query(ThreatEvent).filter(ThreatEvent.timestamp < cutoff).delete()
                session.commit()
                if deleted > 0:
                    self._purged += deleted
                    log.info(f"ThreatDB retention: purged {deleted} events")
                session.close()
            except Exception as e:
                log.error(f"ThreatDB retention error: {e}")

    def export_csv(self, output_path: str = "threat_export.csv", limit: int = 10000) -> str:
        events = self.query_threats(limit=limit)
        if not events:
            return ""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=events[0].keys())
                writer.writeheader()
                writer.writerows(events)
            log.info(f"Exported {len(events)} threats to {output_path}")
            return output_path
        except Exception as e:
            log.error(f"CSV export failed: {e}")
            return ""

    def export_json(self, output_path: str = "threat_export.json", limit: int = 10000) -> str:
        events = self.query_threats(limit=limit)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(events, f, indent=2, default=str)
            log.info(f"Exported {len(events)} threats to {output_path}")
            return output_path
        except Exception as e:
            log.error(f"JSON export failed: {e}")
            return ""

    def close(self):
        self._running = False
        self._flush_buffer()

# Global Singleton
threat_db = ThreatDatabase()
