from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


class AgentType(str, Enum):
    MONITOR = "monitor"
    ANALYZER = "analyzer"
    RESPONDER = "responder"
    ORCHESTRATOR = "orchestrator"
    THREAT_INTEL = "threat_intel"
    DIGITAL_TWIN = "digital_twin"
    COMPLIANCE = "compliance"
    FORENSIC = "forensic"


class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    agent_type: AgentType
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    status: Optional[AgentStatus] = None
    tags: Optional[List[str]] = None


class AgentResponse(BaseModel):
    id: str
    name: str
    agent_type: AgentType
    status: AgentStatus
    description: Optional[str] = None
    config: Dict[str, Any] = {}
    tags: List[str] = []
    last_heartbeat: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AgentActionRequest(BaseModel):
    agent_id: str
    action: str = Field(..., description="Action command for the agent")
    params: Optional[Dict[str, Any]] = None


class AgentActionResponse(BaseModel):
    agent_id: str
    action: str
    status: str
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: Optional[int] = None
    timestamp: datetime


class AgentLog(BaseModel):
    agent_id: str
    level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    message: str
    metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime


class AgentRegistrationResponse(BaseModel):
    agent_id: str
    api_key: str
    status: AgentStatus
    message: str
