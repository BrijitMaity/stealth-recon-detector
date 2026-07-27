"""
models.py — SQLAlchemy ORM Models

Defines the database schema using SQLAlchemy to allow for
seamless scaling to PostgreSQL, MySQL, or Elasticsearch.
"""

from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class ThreatEvent(Base):
    __tablename__ = 'threat_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(50), unique=True, index=True)
    timestamp = Column(DateTime, index=True)
    timestamp_epoch = Column(Float)
    
    source_ip = Column(String(50), index=True)
    source_port = Column(Integer)
    destination_ip = Column(String(50), index=True)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    
    detection_method = Column(String(50))
    confidence = Column(Float)
    severity = Column(Float, index=True)
    threat_type = Column(String(100), index=True)
    threat_intel = Column(Text)
    
    mitre_technique_id = Column(String(20))
    mitre_tactic = Column(String(50))
    
    firewall_action = Column(String(20))
    dpi_result = Column(Text)
    ai_label = Column(String(20))
    
    ml_prediction = Column(Integer)
    prediction_probability = Column(Float)
    
    packet_size = Column(Integer)
    payload_entropy = Column(Float)
    is_port_scan = Column(Boolean)
    unique_ports = Column(Integer)
    duration = Column(Float)
    rate = Column(Float)
    
    raw_event_json = Column(Text)

class IPReputation(Base):
    __tablename__ = 'ip_reputation'
    
    ip = Column(String(50), primary_key=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    total_events = Column(Integer, default=0)
    total_threats = Column(Integer, default=0)
    avg_confidence = Column(Float, default=0.0)
    max_severity = Column(Float, default=0.0)
    tags = Column(String(200), default='[]')
    osint_score = Column(Float, default=0.0)
    is_subnet_blocked = Column(Integer, default=0)

class AlertHistory(Base):
    __tablename__ = 'alert_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String(50), index=True)
    event_id = Column(String(50))
    channel = Column(String(20))
    severity = Column(String(20))
    source_ip = Column(String(50))
    status = Column(String(20), default='sent')
    details = Column(Text)

class PerformanceMetrics(Base):
    __tablename__ = 'performance_metrics'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String(50))
    cpu_percent = Column(Float)
    memory_percent = Column(Float)
    events_per_minute = Column(Float)
    threats_per_minute = Column(Float)
    active_flows = Column(Integer)
    blocked_ips = Column(Integer)
    cache_hit_rate = Column(Float)
