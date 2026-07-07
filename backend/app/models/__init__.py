import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Float, Boolean, DateTime, JSON, Integer, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


def generate_uuid():
    return str(uuid.uuid4())


def utcnow():
    return datetime.now(timezone.utc)


class AgentStatus(str, enum.Enum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


class AgentType(str, enum.Enum):
    MONITOR = "monitor"
    ANALYZER = "analyzer"
    RESPONDER = "responder"
    ORCHESTRATOR = "orchestrator"
    THREAT_INTEL = "threat_intel"
    DIGITAL_TWIN = "digital_twin"
    COMPLIANCE = "compliance"
    FORENSIC = "forensic"


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False, index=True)
    agent_type = Column(SAEnum(AgentType), nullable=False)
    status = Column(SAEnum(AgentStatus), default=AgentStatus.IDLE, nullable=False)
    description = Column(Text, nullable=True)
    api_key = Column(String(256), nullable=True)
    config = Column(JSON, default=dict)
    tags = Column(ARRAY(String), default=list)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentPriority(str, enum.Enum):
    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class IncidentType(str, enum.Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    DOS = "dos"
    INSIDER_THREAT = "insider_threat"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    POLICY_VIOLATION = "policy_violation"
    NETWORK_INTRUSION = "network_intrusion"
    OTHER = "other"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=generate_uuid)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    incident_type = Column(SAEnum(IncidentType), nullable=False)
    status = Column(SAEnum(IncidentStatus), default=IncidentStatus.NEW, nullable=False)
    severity = Column(SAEnum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False)
    priority = Column(SAEnum(IncidentPriority), default=IncidentPriority.P2, nullable=False)
    source = Column(String(200), nullable=True)
    affected_assets = Column(ARRAY(String), default=list)
    mitre_techniques = Column(ARRAY(String), default=list)
    indicators = Column(ARRAY(String), default=list)
    assigned_to = Column(String(100), nullable=True, index=True)
    tags = Column(ARRAY(String), default=list)
    resolution_notes = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(String, primary_key=True, default=generate_uuid)
    incident_id = Column(String, nullable=False, index=True)
    action = Column(String(100), nullable=False)
    actor = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AssetCriticality(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetType(str, enum.Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    DATABASE = "database"
    APPLICATION = "application"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    IOT_DEVICE = "iot_device"
    SECURITY_APPLIANCE = "security_appliance"
    STORAGE = "storage"
    VIRTUAL_MACHINE = "virtual_machine"
    OTHER = "other"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(200), nullable=False, index=True)
    asset_type = Column(SAEnum(AssetType), nullable=False)
    ip_address = Column(String(45), nullable=True, index=True)
    hostname = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)
    os = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    criticality = Column(SAEnum(AssetCriticality), default=AssetCriticality.MEDIUM, nullable=False)
    location = Column(String(200), nullable=True)
    department = Column(String(200), nullable=True, index=True)
    owner = Column(String(100), nullable=True)
    tags = Column(ARRAY(String), default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class RelationshipType(str, enum.Enum):
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    RUNS_ON = "runs_on"
    CONTAINS = "contains"
    COMMUNICATES_WITH = "communicates_with"
    MONITORED_BY = "monitored_by"
    PROTECTED_BY = "protected_by"
    BACKUP_OF = "backup_of"


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"

    id = Column(String, primary_key=True, default=generate_uuid)
    source_asset_id = Column(String, nullable=False, index=True)
    target_asset_id = Column(String, nullable=False, index=True)
    relationship_type = Column(SAEnum(RelationshipType), nullable=False)
    label = Column(String(200), nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class EventCategory(str, enum.Enum):
    ANOMALY = "anomaly"
    THREAT = "threat"
    COMPLIANCE = "compliance"
    SYSTEM = "system"
    NETWORK = "network"
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    USER = "user"


class EventSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=generate_uuid)
    event_type = Column(String(100), nullable=False, index=True)
    category = Column(SAEnum(EventCategory), nullable=False)
    severity = Column(SAEnum(EventSeverity), default=EventSeverity.INFO, nullable=False)
    source = Column(String(200), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)
    tags = Column(ARRAY(String), default=list)
    correlation_id = Column(String(100), nullable=True, index=True)
    processed = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(200), nullable=True)
    roles = Column(ARRAY(String), default=list)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


__all__ = [
    "Base",
    "Agent", "AgentStatus", "AgentType",
    "Incident", "IncidentStatus", "IncidentSeverity", "IncidentPriority", "IncidentType", "IncidentTimeline",
    "Asset", "AssetCriticality", "AssetType",
    "AssetRelationship", "RelationshipType",
    "Event", "EventCategory", "EventSeverity",
    "User",
]
