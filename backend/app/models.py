from sqlalchemy import Column, Integer, String, DateTime, Text
from .database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, index=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True)
    source = Column(String)
    source_ip = Column(String, index=True)
    username = Column(String)
    host = Column(String)
    description = Column(Text)
    category = Column(String, index=True)

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, index=True)
    severity = Column(String, index=True)
    alert_type = Column(String, index=True)
    source_ip = Column(String, index=True)
    destination = Column(String)
    user = Column(String)
    host = Column(String)
    status = Column(String, index=True)
    description = Column(Text)
    detection_reason = Column(Text)
    recommended_response = Column(Text)
    related_events = Column(Text, default="")

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    severity = Column(String, index=True)
    status = Column(String, index=True)
    assigned_analyst = Column(String)
    created = Column(DateTime)
    last_updated = Column(DateTime)
    summary = Column(Text)

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True)
    hostname = Column(String, unique=True)
    ip_address = Column(String)
    operating_system = Column(String)
    status = Column(String)
    risk_level = Column(String)
    last_seen = Column(DateTime)
    security_agent = Column(String)
    open_alerts = Column(Integer, default=0)

class NetworkEvent(Base):
    __tablename__ = "network_events"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    source_ip = Column(String)
    destination_ip = Column(String)
    protocol = Column(String)
    port = Column(Integer)
    action = Column(String)
    event_count = Column(Integer)
    risk_score = Column(Integer)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id = Column(Integer, primary_key=True)
    indicator = Column(String)
    indicator_type = Column(String)
    threat_level = Column(String)
    confidence = Column(Integer)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    status = Column(String)
