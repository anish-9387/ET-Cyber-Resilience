from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import hashlib
import math


EVIDENCE_HALF_LIFE_HOURS = 6.0
DEFAULT_PRIOR = 0.02
LOG_ODDS_FLOOR = -14.0
LOG_ODDS_CEILING = 14.0
CONFIDENCE_GROWTH_K = 0.55
DERIVED_EVIDENCE_INDEPENDENCE = 0.30
MIN_EFFECTIVE_LR = 0.02
MAX_EFFECTIVE_LR = 50.0

CRITICALITY_WEIGHT: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.45,
    "low": 0.2,
    "info": 0.1,
}

SEVERITY_WEIGHT: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.55,
    "low": 0.3,
    "info": 0.15,
}

STATE_THRESHOLDS = [
    ("healthy", 0.2),
    ("suspicious", 0.5),
    ("likely_compromised", 0.8),
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: Optional[datetime]) -> datetime:
    if value is None:
        return utcnow()
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def logit(p: float) -> float:
    p = min(max(p, 1e-9), 1.0 - 1e-9)
    return math.log(p / (1.0 - p))


def sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def decay_weight(age_hours: float, half_life_hours: float = EVIDENCE_HALF_LIFE_HOURS) -> float:
    if age_hours <= 0:
        return 1.0
    return math.pow(0.5, age_hours / half_life_hours)


def derive_state(p_compromised: float) -> str:
    for name, upper in STATE_THRESHOLDS:
        if p_compromised < upper:
            return name
    return "compromised"


def criticality_weight(criticality: str) -> float:
    return CRITICALITY_WEIGHT.get((criticality or "medium").lower(), 0.45)


def severity_weight(severity: str) -> float:
    return SEVERITY_WEIGHT.get((severity or "medium").lower(), 0.55)


@dataclass
class Observation:
    entity_id: str
    source: str = "unknown"
    description: str = ""
    technique_id: Optional[str] = None
    likelihood_ratio: float = 1.0
    severity: str = "medium"
    timestamp: datetime = field(default_factory=utcnow)
    raw: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.timestamp = ensure_aware(self.timestamp)
        self.likelihood_ratio = float(
            min(max(self.likelihood_ratio, MIN_EFFECTIVE_LR), MAX_EFFECTIVE_LR)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "source": self.source,
            "description": self.description,
            "technique_id": self.technique_id,
            "likelihood_ratio": round(self.likelihood_ratio, 4),
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "raw": self.raw,
        }


@dataclass
class Evidence:
    id: str
    entity_id: str
    source: str
    description: str
    technique_id: Optional[str]
    likelihood_ratio: float
    severity: str
    timestamp: datetime
    raw: Dict[str, Any] = field(default_factory=dict)
    derived: bool = False
    origin_entity: Optional[str] = None
    propagation_depth: int = 0
    propagation_path: List[str] = field(default_factory=list)

    @staticmethod
    def make_id(entity_id: str, source: str, description: str, timestamp: datetime) -> str:
        raw = f"{entity_id}|{source}|{description}|{ensure_aware(timestamp).isoformat()}"
        return "ev-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_observation(cls, obs: Observation) -> "Evidence":
        return cls(
            id=cls.make_id(obs.entity_id, obs.source, obs.description, obs.timestamp),
            entity_id=obs.entity_id,
            source=obs.source,
            description=obs.description,
            technique_id=obs.technique_id,
            likelihood_ratio=obs.likelihood_ratio,
            severity=obs.severity,
            timestamp=ensure_aware(obs.timestamp),
            raw=dict(obs.raw or {}),
        )

    def independence_key(self) -> str:
        if self.derived:
            return f"derived:{self.origin_entity or 'unknown'}"
        return f"direct:{self.source}:{self.technique_id or 'na'}"

    def independence_weight(self) -> float:
        return DERIVED_EVIDENCE_INDEPENDENCE if self.derived else 1.0

    def log_likelihood(self) -> float:
        lr = min(max(self.likelihood_ratio, MIN_EFFECTIVE_LR), MAX_EFFECTIVE_LR)
        return math.log(lr)

    def age_hours(self, now: Optional[datetime] = None) -> float:
        now = now or utcnow()
        return max((now - self.timestamp).total_seconds() / 3600.0, 0.0)

    def to_dict(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        age = self.age_hours(now)
        return {
            "id": self.id,
            "entity_id": self.entity_id,
            "source": self.source,
            "description": self.description,
            "technique_id": self.technique_id,
            "likelihood_ratio": round(self.likelihood_ratio, 4),
            "log_likelihood": round(self.log_likelihood(), 4),
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "age_hours": round(age, 3),
            "decay_weight": round(decay_weight(age), 4),
            "derived": self.derived,
            "origin_entity": self.origin_entity,
            "propagation_depth": self.propagation_depth,
            "propagation_path": list(self.propagation_path),
            "raw": self.raw,
        }


@dataclass
class EntityState:
    id: str
    name: str
    entity_type: str
    criticality: str = "medium"
    prior: float = DEFAULT_PRIOR
    p_compromised: float = DEFAULT_PRIOR
    confidence: float = 0.0
    state: str = "healthy"
    evidence: List[Evidence] = field(default_factory=list)
    mission_functions: List[str] = field(default_factory=list)
    last_updated: datetime = field(default_factory=utcnow)
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    is_deception: bool = False
    isolated: bool = False
    aliases: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.last_updated = ensure_aware(self.last_updated)
        self.aliases = {str(alias) for alias in (self.aliases or set()) if str(alias).strip()}
        if not self.evidence:
            self.p_compromised = self.prior
            self.state = derive_state(self.p_compromised)

    def add_evidence(self, evidence: Evidence) -> bool:
        if any(existing.id == evidence.id for existing in self.evidence):
            return False
        self.evidence.append(evidence)
        return True

    def posterior_log_odds(self, now: Optional[datetime] = None) -> float:
        now = now or utcnow()
        accumulated = logit(self.prior)
        for item in self.evidence:
            accumulated += decay_weight(item.age_hours(now)) * item.log_likelihood()
        return min(max(accumulated, LOG_ODDS_FLOOR), LOG_ODDS_CEILING)

    def compute_confidence(self, now: Optional[datetime] = None) -> float:
        now = now or utcnow()
        if not self.evidence:
            return 0.0
        independent: Dict[str, float] = {}
        supporting = 0.0
        refuting = 0.0
        for item in self.evidence:
            weight = decay_weight(item.age_hours(now)) * item.independence_weight()
            key = item.independence_key()
            independent[key] = max(independent.get(key, 0.0), weight)
            contribution = weight * abs(item.log_likelihood())
            if item.log_likelihood() >= 0:
                supporting += contribution
            else:
                refuting += contribution
        effective_count = sum(independent.values())
        breadth = 1.0 - math.exp(-CONFIDENCE_GROWTH_K * effective_count)
        total = supporting + refuting
        agreement = 1.0 if total <= 0 else abs(supporting - refuting) / total
        agreement = 0.5 + 0.5 * agreement
        return round(min(max(breadth * agreement, 0.0), 0.99), 4)

    def recompute(self, now: Optional[datetime] = None) -> Dict[str, float]:
        now = now or utcnow()
        previous_p = self.p_compromised
        previous_confidence = self.confidence
        self.p_compromised = round(sigmoid(self.posterior_log_odds(now)), 6)
        self.confidence = self.compute_confidence(now)
        self.state = derive_state(self.p_compromised)
        self.last_updated = now
        return {
            "delta_p": round(self.p_compromised - previous_p, 6),
            "delta_confidence": round(self.confidence - previous_confidence, 6),
            "previous_p": round(previous_p, 6),
            "previous_confidence": round(previous_confidence, 6),
        }

    def independent_evidence_count(self, now: Optional[datetime] = None) -> int:
        return len({item.independence_key() for item in self.evidence})

    def observed_techniques(self) -> List[str]:
        seen: List[str] = []
        for item in self.evidence:
            if item.technique_id and item.technique_id not in seen:
                seen.append(item.technique_id)
        return seen

    def risk_weight(self) -> float:
        return criticality_weight(self.criticality)

    def to_dict(self, include_evidence: bool = False, now: Optional[datetime] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "entity_type": self.entity_type,
            "criticality": self.criticality,
            "p_compromised": round(self.p_compromised, 6),
            "confidence": round(self.confidence, 4),
            "state": self.state,
            "mission_functions": list(self.mission_functions),
            "last_updated": self.last_updated.isoformat(),
            "attributes": dict(self.attributes),
            "tags": list(self.tags),
            "aliases": sorted(self.aliases),
            "is_deception": self.is_deception,
            "isolated": self.isolated,
            "evidence_count": len(self.evidence),
            "independent_evidence_count": self.independent_evidence_count(),
        }
        payload["evidence"] = (
            [item.to_dict(now) for item in self.evidence] if include_evidence else []
        )
        return payload
