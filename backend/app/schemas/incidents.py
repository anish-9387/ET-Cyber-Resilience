from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentPriority(str, Enum):
    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class IncidentType(str, Enum):
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


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: str
    incident_type: IncidentType
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    priority: IncidentPriority = IncidentPriority.P2
    source: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    indicators: Optional[List[str]] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    priority: Optional[IncidentPriority] = None
    affected_assets: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    indicators: Optional[List[str]] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None
    resolution_notes: Optional[str] = None


class IncidentResponse(BaseModel):
    id: str
    title: str
    description: str
    incident_type: IncidentType
    status: IncidentStatus
    severity: IncidentSeverity
    priority: IncidentPriority
    source: Optional[str] = None
    affected_assets: List[str] = []
    mitre_techniques: List[str] = []
    indicators: List[str] = []
    assigned_to: Optional[str] = None
    tags: List[str] = []
    resolution_notes: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IncidentTimelineEntry(BaseModel):
    incident_id: str
    action: str
    actor: str
    description: str
    metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime


class IncidentSummary(BaseModel):
    id: str
    title: str
    status: IncidentStatus
    severity: IncidentSeverity
    priority: IncidentPriority
    incident_type: IncidentType
    created_at: datetime
    assigned_to: Optional[str] = None
    age_hours: Optional[float] = None


class IncidentSearchParams(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    priority: Optional[IncidentPriority] = None
    incident_type: Optional[IncidentType] = None
    assigned_to: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    tags: Optional[List[str]] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
