from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app.agents.base_agent import BaseAgent
from app.core.logger import logger
from app.core.database import neo4j_driver, qdrant_client
from app.core.llm import llm_manager
from app.core.config import settings
import json, hashlib, numpy as np

EMBEDDING_DIM = 384
_EMBEDDER = None
_EMBEDDER_LOADED = False


def _load_embedder():
    """Lazily load sentence-transformers once per process; None if unavailable."""
    global _EMBEDDER, _EMBEDDER_LOADED
    if _EMBEDDER_LOADED:
        return _EMBEDDER
    _EMBEDDER_LOADED = True
    try:
        from sentence_transformers import SentenceTransformer
        _EMBEDDER = SentenceTransformer(settings.EMBEDDING_MODEL)
        logger.info("Loaded sentence-transformers embedder", model=settings.EMBEDDING_MODEL)
    except Exception as e:
        _EMBEDDER = None
        logger.warning(
            "sentence-transformers unavailable, using hashing fallback",
            model=settings.EMBEDDING_MODEL,
            error=str(e),
        )
    return _EMBEDDER


def _hashing_embedding(text: str, dim: int = EMBEDDING_DIM) -> List[float]:
    """Deterministic character 3-gram hashing vectorizer, L2-normalized.

    Signed hashing (the sign bit of the digest decides +1/-1) keeps the
    expected dot product of unrelated texts near zero. Fully reproducible
    across processes: uses blake2b, never Python's salted `hash()`.
    """
    vector = np.zeros(dim, dtype=np.float64)
    normalized = " ".join((text or "").lower().split())
    if not normalized:
        return vector.tolist()

    padded = f"  {normalized}  "
    for i in range(len(padded) - 2):
        digest = hashlib.blake2b(padded[i:i + 3].encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        vector[value % dim] += 1.0 if (value >> 63) & 1 else -1.0

    norm = float(np.linalg.norm(vector))
    if norm > 0:
        vector /= norm
    return vector.tolist()


def embed_text(text: str) -> Tuple[List[float], str]:
    """Return (vector, method) where method is 'sentence-transformers' or 'hashing'."""
    model = _load_embedder()
    if model is not None:
        try:
            vector = model.encode(text or "", normalize_embeddings=True)
            return [float(v) for v in np.asarray(vector).ravel()], "sentence-transformers"
        except Exception as e:
            logger.warning("Embedding via sentence-transformers failed", error=str(e))
    return _hashing_embedding(text), "hashing"


def stable_point_id(value: str) -> int:
    return int.from_bytes(hashlib.blake2b(str(value).encode("utf-8"), digest_size=8).digest(), "big") % (2 ** 63)


class LearningAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="learning_agent",
            agent_type="learning_memory",
            version=version,
        )
        self.episodic_memory: Dict[str, Dict[str, Any]] = {}
        self.semantic_memory: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.semantic_vectors: Dict[str, Dict[str, Any]] = {}
        self.incident_patterns: Dict[str, Dict[str, Any]] = {}
        self.response_times: Dict[str, List[float]] = defaultdict(list)
        self.similarity_threshold: float = 0.75

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "store")

        try:
            if action == "store":
                return await self._store_incident(input_data)
            elif action == "recall":
                return await self._recall_similar(input_data)
            elif action == "query_pattern":
                return await self._query_pattern(input_data)
            elif action == "get_lessons_learned":
                return self._get_lessons_learned(input_data)
            elif action == "extract_patterns":
                return await self._extract_patterns(input_data)
            elif action == "compare_with_incident":
                return await self._compare_with_incident(input_data)
            elif action == "update_response_time":
                return self._update_response_time(input_data)
            elif action == "get_statistics":
                return self._get_statistics()
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"LearningAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _store_incident(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        incident = input_data.get("incident", input_data)
        incident_id = incident.get("incident_id", incident.get("id"))

        if not incident_id:
            incident_id = hashlib.md5(json.dumps(incident, default=str).encode()).hexdigest()[:16]
            incident["incident_id"] = incident_id

        incident["stored_at"] = datetime.utcnow().isoformat()
        incident["memory_type"] = "episodic"

        self.episodic_memory[incident_id] = incident

        if "attack_chain" in incident or "techniques" in incident:
            pattern_id = await self._extract_and_store_pattern(incident)
            if pattern_id:
                incident["pattern_id"] = pattern_id

        await self._store_in_knowledge_graph(incident)
        await self._store_embedding(incident)

        await self.publish_event("learning.incident_stored", {
            "incident_id": incident_id,
            "techniques": incident.get("techniques", incident.get("mitre_techniques", [])),
        })

        self.update_metrics(True)
        return {"success": True, "incident_id": incident_id}

    async def _recall_similar(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        query = input_data.get("query", input_data)
        max_results = input_data.get("max_results", 10)
        min_similarity = input_data.get("min_similarity", self.similarity_threshold)

        if "techniques" in query or "events" in query or "observations" in query:
            similar = await self._similarity_search(query, min_similarity, max_results)
        else:
            similar = await self._semantic_search(str(query), max_results)

        return {
            "success": True,
            "query": str(query)[:100],
            "total_found": len(similar),
            "results": similar,
        }

    async def _query_pattern(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        pattern_type = input_data.get("pattern_type", "attack_chain")
        technique = input_data.get("technique", input_data.get("technique_id"))
        entity = input_data.get("entity", input_data.get("entity_id"))

        results = []

        if pattern_type == "attack_chain":
            for pid, pattern in self.incident_patterns.items():
                if technique and technique in pattern.get("techniques", []):
                    results.append(pattern)
                if entity and entity in str(pattern.get("entities", [])):
                    results.append(pattern)

        elif pattern_type == "response":
            for eid, incident in self.episodic_memory.items():
                actions = incident.get("response_actions", incident.get("actions_taken", []))
                if actions:
                    for action in actions:
                        if isinstance(action, dict) and action.get("type", action.get("action")) == pattern_type:
                            results.append({
                                "incident_id": eid,
                                "technique": incident.get("technique", incident.get("attack_type")),
                                "action": action,
                                "effectiveness": action.get("effectiveness", 0.5),
                            })

        elif pattern_type == "entity_history":
            for eid, incident in self.episodic_memory.items():
                involved_entities = incident.get("entities", incident.get("involved_entities", []))
                if entity in involved_entities or entity in str(incident):
                    results.append({
                        "incident_id": eid,
                        "timestamp": incident.get("stored_at", incident.get("timestamp")),
                        "summary": incident.get("summary", incident.get("description", ""))[:200],
                    })

        return {
            "success": True,
            "pattern_type": pattern_type,
            "total_results": len(results),
            "results": results[:50],
        }

    def _get_lessons_learned(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = input_data.get("incident_id")
        technique = input_data.get("technique", input_data.get("technique_id"))

        if incident_id and incident_id in self.episodic_memory:
            incident = self.episodic_memory[incident_id]
            return {
                "success": True,
                "incident_id": incident_id,
                "lessons_learned": self._extract_lessons(incident),
            }

        if technique:
            related = [inc for inc in self.episodic_memory.values()
                       if technique in inc.get("techniques", []) or
                       technique in str(inc.get("mitre_techniques", []))]
            if related:
                combined_lessons = []
                for inc in related[:5]:
                    combined_lessons.append(self._extract_lessons(inc))
                return {
                    "success": True,
                    "technique": technique,
                    "incidents_reviewed": len(related),
                    "lessons_learned": combined_lessons,
                }

        return {"success": False, "error": "No lessons found"}

    async def _extract_patterns(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        technique_filter = input_data.get("technique")
        min_occurrences = input_data.get("min_occurrences", 2)

        patterns = defaultdict(list)
        for incident in self.episodic_memory.values():
            techniques = incident.get("techniques", incident.get("mitre_techniques", []))
            for t in techniques:
                if technique_filter and t != technique_filter:
                    continue
                patterns[t].append(incident)

        extracted = []
        for technique, incidents in patterns.items():
            if len(incidents) >= min_occurrences:
                common_actions = self._find_common_elements(
                    [i.get("response_actions", i.get("actions_taken", [])) for i in incidents]
                )
                common_indicators = self._find_common_elements(
                    [i.get("indicators", i.get("iocs", [])) for i in incidents]
                )

                avg_response_time = np.mean([
                    i.get("response_time_minutes", 0) for i in incidents
                    if i.get("response_time_minutes")
                ]) if incidents else 0

                extracted.append({
                    "technique": technique,
                    "occurrence_count": len(incidents),
                    "common_actions": common_actions[:5],
                    "common_indicators": common_indicators[:5],
                    "average_response_time_minutes": round(float(avg_response_time), 1),
                    "recommended_playbook": self._recommend_playbook(technique),
                })

                pattern_id = hashlib.md5(f"pattern_{technique}".encode()).hexdigest()[:12]
                self.incident_patterns[pattern_id] = {
                    "pattern_id": pattern_id,
                    "techniques": [technique],
                    "occurrence_count": len(incidents),
                    "common_actions": common_actions[:5],
                    "recommended_playbook": self._recommend_playbook(technique),
                    "created_at": datetime.utcnow().isoformat(),
                }

        return {
            "success": True,
            "total_patterns": len(extracted),
            "patterns": extracted,
        }

    async def _compare_with_incident(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        current_incident = input_data.get("incident", input_data)
        current_techniques = current_incident.get("techniques", current_incident.get("mitre_techniques", []))

        if not current_techniques:
            return {"success": False, "error": "No techniques to compare"}

        matches = []
        for incident in self.episodic_memory.values():
            stored_techniques = incident.get("techniques", incident.get("mitre_techniques", []))
            common = set(current_techniques) & set(stored_techniques)
            if common:
                similarity = len(common) / max(len(set(current_techniques) | set(stored_techniques)), 1)
                if similarity >= self.similarity_threshold:
                    matches.append({
                        "incident_id": incident.get("incident_id"),
                        "similarity": round(similarity, 4),
                        "common_techniques": list(common),
                        "previous_response": incident.get("response_actions", incident.get("actions_taken", [])),
                        "effectiveness": incident.get("effectiveness", incident.get("response_effectiveness", 0.5)),
                        "time_to_contain_minutes": incident.get("response_time_minutes", 0),
                    })

        matches.sort(key=lambda x: -x["similarity"])

        optimized_response = None
        if matches:
            optimized_response = self._derive_optimized_response(matches)

        return {
            "success": True,
            "matches_found": len(matches),
            "similar_incidents": matches[:10],
            "optimized_response": optimized_response,
            "memory_applied": len(matches) > 0,
        }

    def _update_response_time(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        technique = input_data.get("technique", input_data.get("technique_id"))
        response_time = input_data.get("response_time_minutes", 0)

        if technique and response_time:
            self.response_times[technique].append(float(response_time))
            return {"success": True, "technique": technique, "average_response_time": np.mean(self.response_times[technique])}

        return {"success": False, "error": "technique and response_time_minutes required"}

    def _get_statistics(self) -> Dict[str, Any]:
        return {
            "success": True,
            "statistics": {
                "total_incidents_stored": len(self.episodic_memory),
                "total_patterns_extracted": len(self.incident_patterns),
                "total_semantic_entries": sum(len(v) for v in self.semantic_memory.values()),
                "techniques_in_memory": len(set(
                    t for inc in self.episodic_memory.values()
                    for t in inc.get("techniques", inc.get("mitre_techniques", []))
                )),
                "average_response_time_by_technique": {
                    t: round(float(np.mean(times)), 1)
                    for t, times in self.response_times.items()
                },
            }
        }

    async def _similarity_search(self, query: Dict[str, Any], min_similarity: float, max_results: int) -> List[Dict]:
        query_techniques = set(query.get("techniques", query.get("mitre_techniques", [])))
        query_entities = set(str(e) for e in query.get("entities", query.get("involved_entities", [])))
        query_indicators = set(str(i) for i in query.get("indicators", query.get("iocs", [])))

        results = []
        for incident in self.episodic_memory.values():
            score = 0.0
            factors = []

            stored_techniques = set(incident.get("techniques", incident.get("mitre_techniques", [])))
            if query_techniques and stored_techniques:
                tech_overlap = query_techniques & stored_techniques
                if tech_overlap:
                    tech_score = len(tech_overlap) / max(len(query_techniques | stored_techniques), 1)
                    score += tech_score * 0.5
                    factors.append(f"technique_match:{tech_score}")

            stored_entities = set(str(e) for e in incident.get("entities", incident.get("involved_entities", [])))
            if query_entities and stored_entities:
                entity_overlap = query_entities & stored_entities
                if entity_overlap:
                    entity_score = len(entity_overlap) / max(len(query_entities | stored_entities), 1)
                    score += entity_score * 0.3
                    factors.append(f"entity_match:{entity_score}")

            stored_indicators = set(str(i) for i in incident.get("indicators", incident.get("iocs", [])))
            if query_indicators and stored_indicators:
                ioc_overlap = query_indicators & stored_indicators
                if ioc_overlap:
                    ioc_score = len(ioc_overlap) / max(len(query_indicators | stored_indicators), 1)
                    score += ioc_score * 0.2
                    factors.append(f"ioc_match:{ioc_score}")

            if score >= min_similarity:
                results.append({
                    "incident_id": incident.get("incident_id"),
                    "similarity_score": round(score, 4),
                    "factors": factors,
                    "summary": incident.get("summary", incident.get("description", ""))[:200],
                    "stored_at": incident.get("stored_at"),
                    "techniques": stored_techniques,
                })

        results.sort(key=lambda x: -x["similarity_score"])
        return results[:max_results]

    async def _semantic_search(self, query: str, max_results: int) -> List[Dict]:
        query_lower = query.lower()
        results = []

        for incident in self.episodic_memory.values():
            searchable_text = json.dumps(incident, default=str).lower()
            if query_lower in searchable_text:
                score = searchable_text.count(query_lower) / max(len(searchable_text), 1) * 10
                results.append({
                    "incident_id": incident.get("incident_id"),
                    "similarity_score": round(min(score, 1.0), 4),
                    "summary": incident.get("summary", incident.get("description", ""))[:200],
                    "stored_at": incident.get("stored_at"),
                })

        for pattern_id, pattern in self.incident_patterns.items():
            if query_lower in json.dumps(pattern, default=str).lower():
                results.append({
                    "pattern_id": pattern_id,
                    "similarity_score": 0.8,
                    "type": "pattern",
                    "summary": f"Pattern: {pattern.get('techniques', [])}",
                })

        results.sort(key=lambda x: -x["similarity_score"])
        return results[:max_results]

    async def _extract_and_store_pattern(self, incident: Dict[str, Any]) -> Optional[str]:
        techniques = incident.get("techniques", incident.get("mitre_techniques", []))
        if not techniques:
            return None

        pattern_key = "_".join(sorted(techniques))
        if len(techniques) >= 2:
            pattern_id = hashlib.md5(f"pattern_{pattern_key}".encode()).hexdigest()[:12]
            if pattern_id not in self.incident_patterns:
                self.incident_patterns[pattern_id] = {
                    "pattern_id": pattern_id,
                    "techniques": techniques,
                    "occurrence_count": 0,
                    "first_seen": incident.get("stored_at", datetime.utcnow().isoformat()),
                    "common_indicators": incident.get("indicators", incident.get("iocs", [])),
                }

            self.incident_patterns[pattern_id]["occurrence_count"] += 1
            if "common_indicators" in self.incident_patterns[pattern_id]:
                new_indicators = incident.get("indicators", incident.get("iocs", []))
                existing = set(str(i) for i in self.incident_patterns[pattern_id]["common_indicators"])
                for ind in new_indicators:
                    if str(ind) not in existing:
                        self.incident_patterns[pattern_id]["common_indicators"].append(ind)

            return pattern_id
        return None

    async def _store_in_knowledge_graph(self, incident: Dict[str, Any]):
        try:
            async with neo4j_driver.session() as session:
                incident_id = incident.get("incident_id", "")
                query = """
                MERGE (i:Incident {id: $id})
                SET i.techniques = $techniques,
                    i.summary = $summary,
                    i.severity = $severity,
                    i.timestamp = $timestamp,
                    i.stored_at = $stored_at
                """
                await session.run(query,
                    id=incident_id,
                    techniques=incident.get("techniques", incident.get("mitre_techniques", [])),
                    summary=incident.get("summary", incident.get("description", "")),
                    severity=incident.get("severity", 5),
                    timestamp=incident.get("timestamp", incident.get("stored_at")),
                    stored_at=incident.get("stored_at"),
                )
        except Exception as e:
            logger.warning(f"Failed to store incident in Neo4j", error=str(e))

    async def _store_embedding(self, incident: Dict[str, Any]):
        incident_id = incident.get("incident_id", "")
        text = f"{incident.get('summary', incident.get('description', ''))} {json.dumps(incident.get('techniques', []))}"
        vector, method = embed_text(text)

        self.semantic_vectors[incident_id] = {
            "vector": vector,
            "method": method,
            "text": text[:1000],
        }

        try:
            qdrant_client.upsert(
                collection_name="incident_memory",
                points=[{
                    "id": stable_point_id(incident_id),
                    "vector": vector,
                    "payload": {
                        "incident_id": incident_id,
                        "text": text[:1000],
                        "embedding_method": method,
                        "embedding_dim": len(vector),
                    },
                }]
            )
            logger.debug("Stored incident embedding", incident_id=incident_id, method=method)
        except Exception as e:
            logger.warning(
                "Qdrant unavailable, embedding kept in local semantic memory",
                incident_id=incident_id,
                method=method,
                error=str(e),
            )

    def _extract_lessons(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "incident_id": incident.get("incident_id"),
            "what_happened": incident.get("summary", incident.get("description", ""))[:300],
            "root_cause": incident.get("root_cause", incident.get("cause", "unknown")),
            "response_actions": incident.get("response_actions", incident.get("actions_taken", [])),
            "what_worked": incident.get("what_worked", incident.get("successful_actions", [])),
            "what_didnt_work": incident.get("what_didnt_work", incident.get("failed_actions", [])),
            "improvements": incident.get("improvements", incident.get("recommendations", [])),
            "time_to_detect_minutes": incident.get("time_to_detect", incident.get("detection_time_minutes", 0)),
            "time_to_respond_minutes": incident.get("time_to_respond", incident.get("response_time_minutes", 0)),
        }

    def _find_common_elements(self, lists: List[List]) -> List[Any]:
        if not lists:
            return []
        if len(lists) == 1:
            return lists[0]

        from collections import Counter
        all_items = []
        for lst in lists:
            all_items.extend(lst)
        counter = Counter(str(i) for i in all_items)
        threshold = len(lists) // 2
        return [item for item, count in counter.most_common() if count >= threshold]

    def _recommend_playbook(self, technique: str) -> str:
        playbook_map = {
            "T1566": "phishing_response", "T1059": "process_investigation",
            "T1003": "credential_investigation", "T1021": "lateral_movement_containment",
            "T1486": "ransomware_response", "T1078": "account_investigation",
            "T1190": "vulnerability_response", "T1048": "data_exfiltration_response",
        }
        return playbook_map.get(technique, "general_incident_response")

    def _derive_optimized_response(self, matches: List[Dict]) -> Dict[str, Any]:
        if not matches:
            return {}

        best_match = matches[0]
        response_actions = best_match.get("previous_response", [])

        return {
            "derived_from_incident": best_match["incident_id"],
            "recommended_actions": response_actions,
            "expected_effectiveness": best_match.get("effectiveness", 0.5),
            "expected_time_to_contain_minutes": best_match.get("time_to_contain_minutes", 30),
            "confidence": best_match["similarity"],
        }
