from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class AssetType(str, Enum):
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


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    asset_type: AssetType
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    location: Optional[str] = None
    department: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    criticality: Optional[AssetCriticality] = None
    location: Optional[str] = None
    department: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class AssetResponse(BaseModel):
    id: str
    name: str
    asset_type: AssetType
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    criticality: AssetCriticality
    location: Optional[str] = None
    department: Optional[str] = None
    owner: Optional[str] = None
    tags: List[str] = []
    metadata: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RelationshipType(str, Enum):
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    RUNS_ON = "runs_on"
    CONTAINS = "contains"
    COMMUNICATES_WITH = "communicates_with"
    MONITORED_BY = "monitored_by"
    PROTECTED_BY = "protected_by"
    BACKUP_OF = "backup_of"


class RelationshipCreate(BaseModel):
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    label: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class RelationshipResponse(BaseModel):
    id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    label: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime

    class Config:
        from_attributes = True


class DigitalTwinState(BaseModel):
    asset_id: str
    current_status: str
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    network_in: Optional[float] = None
    network_out: Optional[float] = None
    running_processes: Optional[List[str]] = None
    open_ports: Optional[List[int]] = None
    vulnerabilities: Optional[List[Dict[str, Any]]] = None
    last_updated: datetime


class DigitalTwinSimulation(BaseModel):
    asset_id: str
    scenario: str
    parameters: Dict[str, Any]
    expected_impact: Optional[Dict[str, Any]] = None
    duration_seconds: int


class SimulationResult(BaseModel):
    simulation_id: str
    asset_id: str
    scenario: str
    status: str
    impact_analysis: Dict[str, Any]
    risk_score: Optional[float] = None
    recommendations: List[str] = []
    started_at: datetime
    completed_at: datetime


class AssetGraph(BaseModel):
    nodes: List[AssetResponse]
    relationships: List[RelationshipResponse]


class AssetSearchParams(BaseModel):
    asset_type: Optional[AssetType] = None
    criticality: Optional[AssetCriticality] = None
    department: Optional[str] = None
    location: Optional[str] = None
    search: Optional[str] = None
    tags: Optional[List[str]] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
