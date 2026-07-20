from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
import copy
import hashlib
import math
import re

from app.agents.mitre_mapper import normalize_technique_id
from app.core.logger import logger
from app.world_model.audit import audit
from app.world_model.entity_state import (
    DEFAULT_PRIOR,
    EntityState,
    Evidence,
    Observation,
    criticality_weight,
    ensure_aware,
    severity_weight,
    utcnow,
)


PROPAGATION_DAMPING: Dict[str, Tuple[float, float]] = {
    "authenticates_to": (0.30, 0.60),
    "trusts": (0.35, 0.60),
    "has_credential": (0.55, 0.55),
    "grants_access_to": (0.55, 0.35),
    "can_access": (0.35, 0.20),
    "controls": (0.50, 0.25),
    "runs_on": (0.45, 0.45),
    "depends_on": (0.25, 0.40),
    "backs_up": (0.30, 0.20),
    "communicates_with": (0.25, 0.25),
    "connected_to": (0.18, 0.18),
    "powers": (0.20, 0.10),
    "belongs_to": (0.10, 0.10),
    "protected_by": (0.10, 0.05),
    "lures": (0.15, 0.15),
}

NON_ALNUM = re.compile(r"[^a-z0-9]+")

#: Resolution tiers, most to least authoritative. `resolve()` consults them in
#: this order so that an exact identifier always beats a fuzzy normalized match.
RESOLUTION_TIERS = ("id", "alias", "hostname", "name", "normalized")

MAX_PROPAGATION_DEPTH = 2
MIN_PROPAGATED_LOG_CONTRIBUTION = 0.15
DETECTION_THRESHOLD = 0.5
MAX_OBSERVATION_LOG = 5000


@dataclass
class Relation:
    source: str
    target: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "properties": dict(self.properties),
        }


class CyberWorldModel:
    def __init__(self) -> None:
        self.entities: Dict[str, EntityState] = {}
        self.relations: List[Relation] = []
        self.adjacency: Dict[str, List[Tuple[str, str, str]]] = {}
        # tier -> lowercased key -> entity id. Kept in sync by _index_entity so
        # resolve() is a handful of dict lookups rather than a scan.
        self.identifier_index: Dict[str, Dict[str, str]] = {tier: {} for tier in RESOLUTION_TIERS}
        self.observation_log: List[Dict[str, Any]] = []
        self.detections: Dict[str, Dict[str, Any]] = {}
        self.seed_metadata: Dict[str, Any] = {}
        self.revision: int = 0
        self.created_at: datetime = utcnow()

    def load_seed(self, seed: Dict[str, Any]) -> None:
        self.entities = {}
        self.relations = []
        self.adjacency = {}
        self.identifier_index = {tier: {} for tier in RESOLUTION_TIERS}
        self.observation_log = []
        self.detections = {}
        self.revision = 0
        self.seed_metadata = {
            "name": seed.get("name", "unnamed"),
            "version": seed.get("version", "0"),
            "description": seed.get("description", ""),
            "loaded_at": utcnow().isoformat(),
        }
        for entity in seed.get("entities", []):
            self.add_entity(**entity)
        for relation in seed.get("relations", []):
            self.add_relation(
                relation["source"],
                relation["target"],
                relation["type"],
                relation.get("properties"),
            )
        self.rebuild_identifier_index()
        logger.info(
            "world_model_seed_loaded",
            seed=self.seed_metadata["name"],
            entities=len(self.entities),
            relations=len(self.relations),
        )

    def reset(self) -> None:
        from app.world_model.seed import build_seed

        self.load_seed(build_seed())
        audit.record(
            actor="world_model",
            actor_type="system",
            action="world_model_reset",
            target="global",
            decision="reset world model to seed baseline",
            confidence=1.0,
            reasoning="Operator or API requested a reset of all probabilistic belief state.",
            outcome="reset_complete",
        )

    def add_entity(
        self,
        id: str,
        name: str,
        entity_type: str,
        criticality: str = "medium",
        mission_functions: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
        prior: Optional[float] = None,
        tags: Optional[List[str]] = None,
        is_deception: bool = False,
        aliases: Optional[Iterable[str]] = None,
    ) -> EntityState:
        if id in self.entities:
            return self.entities[id]
        resolved_prior = prior if prior is not None else self._prior_for(entity_type, attributes or {})
        entity = EntityState(
            id=id,
            name=name,
            entity_type=entity_type,
            criticality=criticality,
            prior=resolved_prior,
            p_compromised=resolved_prior,
            mission_functions=list(mission_functions or []),
            attributes=dict(attributes or {}),
            tags=list(tags or []),
            is_deception=is_deception,
            aliases=set(aliases or ()),
        )
        self.entities[id] = entity
        self.adjacency.setdefault(id, [])
        self._index_entity(entity)
        self.revision += 1
        return entity

    # ------------------------------------------------------------------
    # Asset resolution
    #
    # Real telemetry names an asset by whatever the sensor knows: a Windows
    # `Computer` field, a syslog hostname, a Wazuh agent name. None of those are
    # the world model's internal id. `resolve()` maps any of them onto the
    # seeded entity so observations land on the modelled topology instead of
    # spawning orphan nodes with no relations.
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_identifier(value: str) -> str:
        return NON_ALNUM.sub("", str(value).lower())

    def _index_entry(self, tier: str, key: Optional[str], entity_id: str) -> None:
        if not key:
            return
        key = str(key).strip().lower()
        if not key:
            return
        # First writer wins: the seed is authoritative over later discoveries.
        self.identifier_index[tier].setdefault(key, entity_id)

    def _hostnames_for(self, entity: EntityState) -> List[str]:
        candidates: List[str] = []
        for key in ("hostname", "host", "fqdn", "computer_name"):
            value = entity.attributes.get(key)
            if value:
                candidates.append(str(value))
        for key in ("hostnames", "fqdns"):
            values = entity.attributes.get(key) or []
            if isinstance(values, (list, tuple, set)):
                candidates.extend(str(item) for item in values)
        return candidates

    def _index_entity(self, entity: EntityState) -> None:
        self._index_entry("id", entity.id, entity.id)
        for alias in sorted(entity.aliases):
            self._index_entry("alias", alias, entity.id)
        for hostname in self._hostnames_for(entity):
            self._index_entry("hostname", hostname, entity.id)
        self._index_entry("name", entity.name, entity.id)
        for candidate in [entity.id, *sorted(entity.aliases), *self._hostnames_for(entity), entity.name]:
            self._index_entry("normalized", self._normalize_identifier(candidate), entity.id)

    def rebuild_identifier_index(self) -> None:
        self.identifier_index = {tier: {} for tier in RESOLUTION_TIERS}
        # Deterministic: index in id order so collisions resolve the same way
        # on every rebuild.
        for entity_id in sorted(self.entities):
            self._index_entity(self.entities[entity_id])

    def resolve(self, identifier: str) -> Optional[EntityState]:
        """Map any telemetry-supplied identifier onto a modelled entity.

        Priority: exact id, alias, hostname, name, then a normalized form with
        all non-alphanumerics stripped. All comparisons are case-insensitive.
        Returns None when nothing matches - the caller decides whether that is
        a newly discovered asset.
        """
        if not identifier:
            return None
        key = str(identifier).strip().lower()
        if not key:
            return None
        for tier in RESOLUTION_TIERS:
            lookup = key if tier != "normalized" else self._normalize_identifier(key)
            entity_id = self.identifier_index[tier].get(lookup)
            if entity_id and entity_id in self.entities:
                return self.entities[entity_id]
        return None

    def discover_entity(
        self,
        identifier: str,
        entity_type: str = "unknown",
        name: Optional[str] = None,
        criticality: str = "medium",
    ) -> EntityState:
        """Register an asset that appeared on the wire but is not in the model.

        An unrecognised host is itself a finding, so the entity is tagged
        unmanaged/discovered rather than silently blending into the seed.
        """
        entity = self.add_entity(
            id=identifier,
            name=name or identifier,
            entity_type=entity_type,
            criticality=criticality,
            attributes={"managed": False, "discovered": True, "first_seen": utcnow().isoformat()},
            tags=["discovered", "unmanaged"],
            aliases={identifier},
        )
        logger.warning(
            "world_model_unmanaged_asset_discovered",
            entity_id=identifier,
            entity_type=entity_type,
            note="identifier did not resolve to any seeded asset; treating as an unmanaged device on the network",
        )
        return entity

    def _prior_for(self, entity_type: str, attributes: Dict[str, Any]) -> float:
        base = DEFAULT_PRIOR
        if attributes.get("internet_facing"):
            base += 0.03
        if attributes.get("cves"):
            base += 0.01 * min(len(attributes["cves"]), 3)
        if attributes.get("mfa_enabled") is False:
            base += 0.01
        if attributes.get("patchable") is False:
            base += 0.01
        if str(attributes.get("strength", "")).lower() == "weak":
            base += 0.02
        if attributes.get("stored_securely") is False:
            base += 0.01
        return round(min(base, 0.2), 6)

    def add_relation(
        self,
        source: str,
        target: str,
        relation_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Optional[Relation]:
        if source not in self.entities or target not in self.entities:
            return None
        for existing in self.relations:
            if existing.source == source and existing.target == target and existing.type == relation_type:
                return existing
        relation = Relation(source=source, target=target, type=relation_type, properties=dict(properties or {}))
        self.relations.append(relation)
        self.adjacency.setdefault(source, []).append((target, relation_type, "out"))
        self.adjacency.setdefault(target, []).append((source, relation_type, "in"))
        self.revision += 1
        return relation

    def remove_relations_for(self, entity_id: str, relation_types: Optional[Iterable[str]] = None) -> List[Relation]:
        allowed = set(relation_types) if relation_types else None
        removed: List[Relation] = []
        kept: List[Relation] = []
        for relation in self.relations:
            touches = relation.source == entity_id or relation.target == entity_id
            matches_type = allowed is None or relation.type in allowed
            if touches and matches_type:
                removed.append(relation)
            else:
                kept.append(relation)
        if removed:
            self.relations = kept
            self._rebuild_adjacency()
            self.revision += 1
        return removed

    def _rebuild_adjacency(self) -> None:
        self.adjacency = {entity_id: [] for entity_id in self.entities}
        for relation in self.relations:
            self.adjacency.setdefault(relation.source, []).append((relation.target, relation.type, "out"))
            self.adjacency.setdefault(relation.target, []).append((relation.source, relation.type, "in"))

    def get_entity(self, entity_id: str) -> Optional[EntityState]:
        return self.entities.get(entity_id)

    def all_entities(self) -> List[EntityState]:
        return sorted(self.entities.values(), key=lambda e: (-e.p_compromised, e.id))

    def neighbors(self, entity_id: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for neighbor_id, relation_type, direction in self.adjacency.get(entity_id, []):
            neighbor = self.entities.get(neighbor_id)
            if not neighbor:
                continue
            results.append(
                {
                    "id": neighbor_id,
                    "name": neighbor.name,
                    "entity_type": neighbor.entity_type,
                    "relation": relation_type,
                    "direction": direction,
                    "p_compromised": round(neighbor.p_compromised, 6),
                    "criticality": neighbor.criticality,
                }
            )
        return sorted(results, key=lambda item: (item["relation"], item["id"]))

    def entities_by_type(self, entity_type: str) -> List[EntityState]:
        return [e for e in self.all_entities() if e.entity_type == entity_type]

    def compromised_entities(self, threshold: float = DETECTION_THRESHOLD) -> List[EntityState]:
        return [e for e in self.all_entities() if e.p_compromised >= threshold]

    def hop_distance(self, source_id: str, target_id: str, max_depth: int = 6) -> Optional[int]:
        if source_id == target_id:
            return 0
        visited = {source_id}
        frontier = deque([(source_id, 0)])
        while frontier:
            current, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            for neighbor_id, _relation_type, _direction in sorted(self.adjacency.get(current, [])):
                if neighbor_id in visited:
                    continue
                if neighbor_id == target_id:
                    return depth + 1
                visited.add(neighbor_id)
                frontier.append((neighbor_id, depth + 1))
        return None

    def distance_from_compromised(self, target_id: str, threshold: float = 0.4) -> Optional[int]:
        sources = [e.id for e in self.all_entities() if e.p_compromised >= threshold]
        if not sources:
            return None
        distances = [d for d in (self.hop_distance(s, target_id) for s in sources) if d is not None]
        return min(distances) if distances else None

    async def ingest_observation(self, obs: Observation) -> List[str]:
        entity = self.resolve(obs.entity_id)
        if entity is None:
            raw = obs.raw or {}
            entity = self.discover_entity(
                identifier=obs.entity_id,
                entity_type=raw.get("entity_type", "unknown"),
                name=raw.get("entity_name", obs.entity_id),
                criticality=raw.get("criticality", "medium"),
            )

        # Evidence is filed against the resolved entity, not the raw identifier.
        if entity.id != obs.entity_id:
            obs.raw = {**(obs.raw or {}), "observed_identifier": obs.entity_id, "resolved_entity_id": entity.id}
            obs.entity_id = entity.id

        now = ensure_aware(obs.timestamp)
        evidence = Evidence.from_observation(obs)
        updated: List[str] = []

        if entity.add_evidence(evidence):
            delta = entity.recompute(now)
            updated.append(entity.id)
            self._record_detection(entity, obs, now)
            audit.record_belief_update(
                entity_id=entity.id,
                entity_name=entity.name,
                delta=delta,
                evidence=[evidence.to_dict(now)],
                reasoning=(
                    f"Bayesian log-odds fusion: prior logit({entity.prior:.4f}) plus "
                    f"{len(entity.evidence)} decayed evidence terms; this observation "
                    f"contributed log(LR)={evidence.log_likelihood():.4f} from source '{obs.source}'."
                ),
                confidence=entity.confidence,
            )
            updated.extend(self._propagate(entity, evidence, now))

        self.observation_log.append(
            {
                "sequence": len(self.observation_log) + 1,
                "observation": obs.to_dict(),
                "evidence_id": evidence.id,
                "updated_entities": list(dict.fromkeys(updated)),
                "global_risk_after": self.global_risk(),
            }
        )
        if len(self.observation_log) > MAX_OBSERVATION_LOG:
            self.observation_log = self.observation_log[-MAX_OBSERVATION_LOG:]

        self.revision += 1
        await self._persist_opportunistically(entity, evidence)
        return list(dict.fromkeys(updated))

    def _fan_out(self, entity_id: str, relation_type: str, direction: str) -> int:
        return max(
            len(
                [
                    edge
                    for edge in self.adjacency.get(entity_id, [])
                    if edge[1] == relation_type and edge[2] == direction
                ]
            ),
            1,
        )

    def _propagate(self, origin: EntityState, evidence: Evidence, now: datetime) -> List[str]:
        origin_log_lr = evidence.log_likelihood()
        if abs(origin_log_lr) < MIN_PROPAGATED_LOG_CONTRIBUTION:
            return []
        updated: List[str] = []
        visited = {origin.id}
        frontier: List[Tuple[str, int, float, List[str]]] = [(origin.id, 0, 1.0, [origin.id])]

        while frontier:
            current_id, depth, damping_product, path = frontier.pop(0)
            if depth >= MAX_PROPAGATION_DEPTH:
                continue
            for neighbor_id, relation_type, direction in sorted(self.adjacency.get(current_id, [])):
                if neighbor_id in visited:
                    continue
                damping_pair = PROPAGATION_DAMPING.get(relation_type)
                if damping_pair is None:
                    continue
                damping = damping_pair[0] if direction == "out" else damping_pair[1]
                fan_out = self._fan_out(current_id, relation_type, direction)
                normalized_damping = damping / math.sqrt(fan_out)
                next_damping = damping_product * normalized_damping
                log_contribution = next_damping * origin_log_lr
                if abs(log_contribution) < MIN_PROPAGATED_LOG_CONTRIBUTION:
                    continue
                effective_lr = math.exp(log_contribution)
                neighbor = self.entities.get(neighbor_id)
                if neighbor is None:
                    continue
                visited.add(neighbor_id)
                next_path = path + [neighbor_id]
                derived = Evidence(
                    id=Evidence.make_id(
                        neighbor_id,
                        f"propagation:{evidence.id}",
                        f"{relation_type}:{'>'.join(next_path)}",
                        evidence.timestamp,
                    ),
                    entity_id=neighbor_id,
                    source=f"world_model.propagation[{evidence.source}]",
                    description=(
                        f"Belief propagated from {origin.name} over '{relation_type}' "
                        f"({direction}-edge, depth {depth + 1}, fan-out {fan_out}, "
                        f"damping {next_damping:.4f})"
                    ),
                    technique_id=evidence.technique_id,
                    likelihood_ratio=effective_lr,
                    severity=evidence.severity,
                    timestamp=evidence.timestamp,
                    raw={
                        "origin_evidence_id": evidence.id,
                        "relation_type": relation_type,
                        "edge_direction": direction,
                        "fan_out": fan_out,
                        "damping": round(next_damping, 6),
                        "log_contribution": round(log_contribution, 6),
                    },
                    derived=True,
                    origin_entity=origin.id,
                    propagation_depth=depth + 1,
                    propagation_path=next_path,
                )
                if neighbor.add_evidence(derived):
                    delta = neighbor.recompute(now)
                    updated.append(neighbor_id)
                    audit.record_belief_update(
                        entity_id=neighbor_id,
                        entity_name=neighbor.name,
                        delta=delta,
                        evidence=[derived.to_dict(now)],
                        reasoning=(
                            f"Structural belief propagation along {'->'.join(next_path)}: "
                            f"log(LR)={origin_log_lr:.4f} at the origin, damped in log-odds space by "
                            f"{next_damping:.4f} (relation '{relation_type}', {direction}-edge, "
                            f"fan-out {fan_out}) -> effective LR {effective_lr:.4f}."
                        ),
                        confidence=neighbor.confidence,
                    )
                frontier.append((neighbor_id, depth + 1, next_damping, next_path))
        return updated

    def _record_detection(self, entity: EntityState, obs: Observation, now: datetime) -> None:
        record = self.detections.setdefault(
            entity.id,
            {"first_activity": now, "detected_at": None, "first_technique": obs.technique_id},
        )
        if obs.technique_id and not record.get("first_technique"):
            record["first_technique"] = obs.technique_id
        if now < record["first_activity"]:
            record["first_activity"] = now
        if record["detected_at"] is None and entity.p_compromised >= DETECTION_THRESHOLD:
            record["detected_at"] = now

    async def _persist_opportunistically(self, entity: EntityState, evidence: Evidence) -> None:
        try:
            from app.core.database import neo4j_driver

            async with neo4j_driver.session() as session:
                await session.run(
                    "MERGE (n:WorldModelEntity {id: $id}) "
                    "SET n.name = $name, n.entity_type = $entity_type, "
                    "n.p_compromised = $p, n.confidence = $confidence, n.state = $state, "
                    "n.last_updated = $last_updated",
                    id=entity.id,
                    name=entity.name,
                    entity_type=entity.entity_type,
                    p=entity.p_compromised,
                    confidence=entity.confidence,
                    state=entity.state,
                    last_updated=entity.last_updated.isoformat(),
                )
        except Exception as exc:
            logger.debug(
                "world_model_neo4j_persist_skipped",
                entity_id=entity.id,
                evidence_id=evidence.id,
                error=str(exc),
            )

    def global_risk(self) -> float:
        if not self.entities:
            return 0.0
        numerator = 0.0
        denominator = 0.0
        for entity in self.entities.values():
            weight = criticality_weight(entity.criticality)
            numerator += weight * entity.p_compromised
            denominator += weight
        return round(numerator / denominator, 6) if denominator else 0.0

    def observed_techniques(self) -> List[str]:
        """Distinct parent ATT&CK techniques, in first-observed order.

        Anything that is not a real technique id (sentinels such as "UNKNOWN"
        from unmapped events) is dropped rather than counted, and
        sub-techniques collapse to their parent so set comparisons against the
        campaign and objective tables share one alphabet.
        """
        ordered: List[str] = []
        for record in self.observation_log:
            technique_id = normalize_technique_id(record["observation"].get("technique_id"))
            if technique_id and technique_id not in ordered:
                ordered.append(technique_id)
        return ordered

    def observed_technique_events(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for record in self.observation_log:
            observation = record["observation"]
            technique_id = normalize_technique_id(observation.get("technique_id"))
            if technique_id:
                events.append(
                    {
                        "technique_id": technique_id,
                        "entity_id": observation["entity_id"],
                        "timestamp": observation["timestamp"],
                        "severity": observation["severity"],
                        "source": observation["source"],
                    }
                )
        return events

    def mttd_minutes(self) -> Optional[float]:
        durations: List[float] = []
        for record in self.detections.values():
            if record.get("detected_at") is None:
                continue
            delta = (record["detected_at"] - record["first_activity"]).total_seconds() / 60.0
            durations.append(max(delta, 0.0))
        if not durations:
            return None
        return round(sum(durations) / len(durations), 4)

    def snapshot_id(self) -> str:
        fingerprint = "|".join(
            f"{entity.id}:{entity.p_compromised:.6f}:{entity.confidence:.4f}"
            for entity in sorted(self.entities.values(), key=lambda e: e.id)
        )
        digest = hashlib.sha1(f"{self.revision}|{fingerprint}".encode("utf-8")).hexdigest()[:12]
        return f"wm-{self.revision:06d}-{digest}"

    def snapshot(self) -> Dict[str, Any]:
        now = utcnow()
        entities = self.all_entities()
        return {
            "snapshot_id": self.snapshot_id(),
            "timestamp": now.isoformat(),
            "seed": self.seed_metadata,
            "entity_count": len(entities),
            "relation_count": len(self.relations),
            "global_risk": self.global_risk(),
            "compromised_count": len([e for e in entities if e.p_compromised >= 0.8]),
            "likely_compromised_count": len([e for e in entities if 0.5 <= e.p_compromised < 0.8]),
            "suspicious_count": len([e for e in entities if 0.2 <= e.p_compromised < 0.5]),
            "observation_count": len(self.observation_log),
            "observed_techniques": self.observed_techniques(),
            "mttd_minutes": self.mttd_minutes(),
            "entities": [entity.to_dict(now=now) for entity in entities],
        }

    def graph(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": entity.id,
                    "label": entity.name,
                    "type": entity.entity_type,
                    "p_compromised": round(entity.p_compromised, 6),
                    "confidence": round(entity.confidence, 4),
                    "criticality": entity.criticality,
                    "state": entity.state,
                    "is_deception": entity.is_deception,
                    "isolated": entity.isolated,
                }
                for entity in self.all_entities()
            ],
            "edges": [
                {"source": relation.source, "target": relation.target, "type": relation.type}
                for relation in self.relations
            ],
        }

    def attacker_belief(self) -> Dict[str, Any]:
        from app.world_model.attacker_belief import infer_attacker_belief

        return infer_attacker_belief(self)

    def defender_belief(self) -> Dict[str, Any]:
        from app.world_model.defender_belief import assess_defender_belief

        return assess_defender_belief(self)

    def forecast(self, horizon_minutes: int = 60) -> Dict[str, Any]:
        from app.world_model.forecast import generate_futures

        return generate_futures(self, horizon_minutes)

    def mission_impact(self) -> Dict[str, Any]:
        from app.world_model.mission_impact import compute_mission_impact

        return compute_mission_impact(self)

    def clone(self) -> "CyberWorldModel":
        return copy.deepcopy(self)

    def evidence_summary(self, limit: int = 5) -> List[Dict[str, Any]]:
        now = utcnow()
        collected: List[Tuple[float, Dict[str, Any]]] = []
        for entity in self.entities.values():
            for item in entity.evidence:
                if item.derived:
                    continue
                score = severity_weight(item.severity) * abs(item.log_likelihood())
                collected.append((score, item.to_dict(now)))
        collected.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
        return [payload for _score, payload in collected[:limit]]


world_model = CyberWorldModel()
