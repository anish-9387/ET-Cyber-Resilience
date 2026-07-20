from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib
import threading

from app.core.logger import logger


ACTOR_TYPES = {"ai_agent", "human", "system"}
BELIEF_DELTA_THRESHOLD = 0.05
MAX_RECORDS = 5000


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AuditRecord:
    id: str
    timestamp: datetime
    actor: str
    actor_type: str
    action: str
    target: str
    decision: str
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reasoning: str = ""
    alternatives_considered: List[Dict[str, Any]] = field(default_factory=list)
    approved_by: Optional[str] = None
    rollback_available: bool = False
    outcome: str = "recorded"
    sequence: int = 0
    previous_hash: str = ""
    record_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "sequence": self.sequence,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "actor_type": self.actor_type,
            "action": self.action,
            "target": self.target,
            "decision": self.decision,
            "confidence": round(self.confidence, 4),
            "evidence": self.evidence,
            "reasoning": self.reasoning,
            "alternatives": self.alternatives_considered,
            "alternatives_considered": self.alternatives_considered,
            "approved_by": self.approved_by,
            "rollback_available": self.rollback_available,
            "outcome": self.outcome,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


class AuditTrail:
    def __init__(self) -> None:
        self._records: List[AuditRecord] = []
        self._index: Dict[str, AuditRecord] = {}
        self._lock = threading.Lock()
        self._sequence = 0

    def record(
        self,
        actor: str,
        action: str,
        target: str,
        decision: str,
        confidence: float = 0.0,
        actor_type: str = "ai_agent",
        evidence: Optional[List[Dict[str, Any]]] = None,
        reasoning: str = "",
        alternatives_considered: Optional[List[Dict[str, Any]]] = None,
        approved_by: Optional[str] = None,
        rollback_available: bool = False,
        outcome: str = "recorded",
    ) -> Dict[str, Any]:
        if actor_type not in ACTOR_TYPES:
            actor_type = "system"
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
            previous_hash = self._records[-1].record_hash if self._records else ""
            timestamp = _utcnow()
            digest_source = "|".join(
                [
                    str(sequence),
                    timestamp.isoformat(),
                    actor,
                    actor_type,
                    action,
                    target,
                    decision,
                    f"{confidence:.6f}",
                    previous_hash,
                ]
            )
            record_hash = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()
            record = AuditRecord(
                id=f"audit-{sequence:06d}-{record_hash[:8]}",
                timestamp=timestamp,
                actor=actor,
                actor_type=actor_type,
                action=action,
                target=target,
                decision=decision,
                confidence=float(confidence),
                evidence=list(evidence or []),
                reasoning=reasoning,
                alternatives_considered=list(alternatives_considered or []),
                approved_by=approved_by,
                rollback_available=rollback_available,
                outcome=outcome,
                sequence=sequence,
                previous_hash=previous_hash,
                record_hash=record_hash,
            )
            self._records.append(record)
            self._index[record.id] = record
            if len(self._records) > MAX_RECORDS:
                dropped = self._records[: len(self._records) - MAX_RECORDS]
                self._records = self._records[-MAX_RECORDS:]
                for item in dropped:
                    self._index.pop(item.id, None)
        # Debug, not info: the world model emits a belief_update record per
        # entity per observation, so at INFO a single scenario replay buries
        # every other log line (and the evaluation console report) under
        # hundreds of these. The authoritative record is the trail itself,
        # readable via GET /audit/trail - this is only a mirror for tracing.
        logger.debug(
            "audit_record",
            audit_id=record.id,
            actor=actor,
            action=action,
            target=target,
            decision=decision,
        )
        return record.to_dict()

    def record_belief_update(
        self,
        entity_id: str,
        entity_name: str,
        delta: Dict[str, float],
        evidence: List[Dict[str, Any]],
        reasoning: str,
        confidence: float,
    ) -> Optional[Dict[str, Any]]:
        if abs(delta.get("delta_p", 0.0)) < BELIEF_DELTA_THRESHOLD:
            return None
        direction = "raised" if delta.get("delta_p", 0.0) > 0 else "lowered"
        return self.record(
            actor="world_model.bayesian_fusion",
            actor_type="ai_agent",
            action="belief_update",
            target=entity_id,
            decision=(
                f"{direction} P(compromised) for {entity_name} from "
                f"{delta.get('previous_p', 0.0):.3f} to "
                f"{delta.get('previous_p', 0.0) + delta.get('delta_p', 0.0):.3f}"
            ),
            confidence=confidence,
            evidence=evidence,
            reasoning=reasoning,
            outcome="belief_state_changed",
        )

    def all_records(self) -> List[Dict[str, Any]]:
        return [record.to_dict() for record in self._records]

    def query(
        self,
        limit: int = 100,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
        actor_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        selected = list(reversed(self._records))
        if actor:
            selected = [r for r in selected if actor.lower() in r.actor.lower()]
        if action:
            selected = [r for r in selected if action.lower() in r.action.lower()]
        if target:
            selected = [r for r in selected if target.lower() in r.target.lower()]
        if actor_type:
            selected = [r for r in selected if r.actor_type == actor_type]
        return [record.to_dict() for record in selected[: max(limit, 0)]]

    def get(self, record_id: str) -> Optional[Dict[str, Any]]:
        record = self._index.get(record_id)
        return record.to_dict() if record else None

    def verify_chain(self) -> Dict[str, Any]:
        broken: List[str] = []
        previous_hash = ""
        for record in self._records:
            if record.previous_hash != previous_hash:
                broken.append(record.id)
            previous_hash = record.record_hash
        return {
            "records": len(self._records),
            "intact": not broken,
            "broken_at": broken,
        }

    def stats(self) -> Dict[str, Any]:
        by_action: Dict[str, int] = {}
        by_actor_type: Dict[str, int] = {}
        for record in self._records:
            by_action[record.action] = by_action.get(record.action, 0) + 1
            by_actor_type[record.actor_type] = by_actor_type.get(record.actor_type, 0) + 1
        return {
            "total_records": len(self._records),
            "by_action": by_action,
            "by_actor_type": by_actor_type,
            "chain": self.verify_chain(),
        }

    def reset(self) -> None:
        with self._lock:
            self._records = []
            self._index = {}
            self._sequence = 0


audit = AuditTrail()
