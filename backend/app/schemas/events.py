from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class EventSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventCategory(str, Enum):
    ANOMALY = "anomaly"
    THREAT = "threat"
    COMPLIANCE = "compliance"
    SYSTEM = "system"
    NETWORK = "network"
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    USER = "user"


class EventCreate(BaseModel):
    event_type: str
    category: EventCategory
    severity: EventSeverity = EventSeverity.INFO
    source: str
    title: str
    description: str
    raw_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    correlation_id: Optional[str] = None


class EventResponse(BaseModel):
    id: str
    event_type: str
    category: EventCategory
    severity: EventSeverity
    source: str
    title: str
    description: str
    raw_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: List[str] = []
    correlation_id: Optional[str] = None
    processed: bool = False
    timestamp: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class EventSearchParams(BaseModel):
    category: Optional[EventCategory] = None
    severity: Optional[EventSeverity] = None
    source: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    tags: Optional[List[str]] = None
    processed: Optional[bool] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)


class EventProcessResult(BaseModel):
    event_id: str
    status: str
    actions_taken: List[str] = []
    enriched_data: Optional[Dict[str, Any]] = None
    processing_time_ms: int


class EventStats(BaseModel):
    total_events: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_source: Dict[str, int]
    time_range_hours: int
