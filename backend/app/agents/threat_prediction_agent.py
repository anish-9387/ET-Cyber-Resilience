from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from app.agents.base_agent import BaseAgent
from app.agents.mitre_mapper import mitre_mapper, TACTIC_ORDER
from app.core.logger import logger
from app.core.llm import llm_manager
import json, re


TECHNIQUE_TRANSITION_MATRIX = {
    "T1566": [("T1204", 0.85), ("T1059", 0.70)],
    "T1204": [("T1059", 0.80), ("T1547", 0.45), ("T1562", 0.40)],
    "T1059": [("T1003", 0.55), ("T1547", 0.45), ("T1562", 0.50), ("T1068", 0.40)],
    "T1190": [("T1059", 0.75), ("T1068", 0.60)],
    "T1003": [("T1087", 0.70), ("T1021", 0.65), ("T1550", 0.50)],
    "T1078": [("T1098", 0.55), ("T1021", 0.60)],
    "T1087": [("T1069", 0.70), ("T1021", 0.60), ("T1046", 0.55)],
    "T1069": [("T1021", 0.65)],
    "T1021": [("T1005", 0.60), ("T1570", 0.55), ("T1550", 0.50)],
    "T1550": [("T1021", 0.70), ("T1003", 0.45)],
    "T1570": [("T1021", 0.45), ("T1055", 0.40)],
    "T1547": [("T1003", 0.50), ("T1055", 0.40)],
    "T1562": [("T1003", 0.50), ("T1070", 0.45)],
    "T1068": [("T1003", 0.55), ("T1134", 0.40)],
    "T1046": [("T1021", 0.55), ("T1135", 0.40)],
    "T1005": [("T1039", 0.60), ("T1048", 0.55)],
    "T1039": [("T1048", 0.65), ("T1567", 0.50)],
    "T1048": [("T1567", 0.60)],
    "T1486": [],
    "T1490": [],
    "T1098": [("T1021", 0.55), ("T1003", 0.40)],
    "T1070": [("T1562", 0.40)],
    "T1134": [("T1068", 0.45), ("T1098", 0.40)],
    "T1055": [("T1003", 0.50), ("T1562", 0.45)],
}


class ThreatPredictionAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="threat_prediction_agent",
            agent_type="threat_prediction",
            version=version,
        )
        self.prediction_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "predict")

        try:
            if action == "predict":
                return await self._predict(input_data)
            elif action == "predict_sequence":
                return await self._predict_sequence(input_data)
            elif action == "get_predictions":
                return self._get_predictions(input_data)
            elif action == "evaluate_prediction":
                return await self._evaluate_prediction(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"ThreatPredictionAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _predict(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        observations = input_data.get("observations", [input_data])
        environment = input_data.get("environment", {})
        use_llm = input_data.get("use_llm", False)

        if not observations:
            return {"success": False, "error": "No observations provided"}

        current_techniques = []
        current_tactics = set()
        for obs in observations:
            mapped = mitre_mapper.map_event(obs)
            if mapped["mapped"]:
                current_techniques.append(mapped["technique_id"])
                current_tactics.add(mapped["tactic"])

        if not current_techniques:
            return {"success": False, "error": "Could not map observations to MITRE techniques"}

        predictions = await self._generate_predictions(current_techniques, current_tactics, environment)

        if use_llm:
            llm_predictions = await self._llm_enhance_predictions(observations, environment)
            predictions = self._merge_predictions(predictions, llm_predictions)

        defensive_actions = self._recommend_defensive_actions(predictions, environment)

        result = {
            "success": True,
            "current_techniques": current_techniques,
            "current_tactics": list(current_tactics),
            "predictions": predictions,
            "defensive_actions": defensive_actions,
            "temporal_context": self._analyze_temporal_pattern(current_techniques),
            "prediction_id": self._generate_prediction_id(current_techniques),
            "timestamp": datetime.utcnow().isoformat(),
        }

        self._store_prediction(result["prediction_id"], result)

        await self.publish_event("threat.prediction", {
            "prediction_id": result["prediction_id"],
            "current_techniques": current_techniques,
            "top_prediction": predictions[0] if predictions else None,
        })

        return result

    async def _predict_sequence(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        events = input_data.get("events", [])
        if not events:
            return {"success": False, "error": "No events provided"}

        return await self._predict({"observations": events, "environment": input_data.get("environment", {})})

    async def _generate_predictions(
        self, techniques: List[str], tactics: set, environment: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        next_techniques = defaultdict(float)

        for tid in techniques:
            if tid in TECHNIQUE_TRANSITION_MATRIX:
                for next_tid, prob in TECHNIQUE_TRANSITION_MATRIX[tid]:
                    next_techniques[next_tid] = max(next_techniques.get(next_tid, 0), prob)

        for tid in techniques:
            next_tactics_list = mitre_mapper.get_next_likely_techniques(tid)
            for nt in next_tactics_list:
                nid = nt.get("technique_id")
                if nid and nid not in techniques:
                    weight = 0.4 if nt["tactic"] in {"lateral_movement", "impact", "exfiltration"} else 0.2
                    next_techniques[nid] = max(next_techniques.get(nid, 0), weight)

        current_tactic_indices = [self._get_tactic_index(t) for t in tactics if t]
        if current_tactic_indices:
            max_tactic_idx = max(current_tactic_indices)
            if max_tactic_idx < len(TACTIC_ORDER) - 1:
                next_tactics = TACTIC_ORDER[max_tactic_idx + 1:max_tactic_idx + 3]
                for nt in next_tactics:
                    nt_techniques = mitre_mapper.get_techniques_for_tactic(nt)
                    for tid, info in nt_techniques.items():
                        if tid not in techniques:
                            next_techniques[tid] = max(next_techniques.get(tid, 0), 0.3)

        critical_targets = self._infer_targets(environment)

        sorted_predictions = sorted(next_techniques.items(), key=lambda x: -x[1])
        predictions = []
        for tid, prob in sorted_predictions[:5]:
            technique_info = mitre_mapper.get_technique(tid)
            if technique_info:
                eta_minutes = self._estimate_eta(tid, techniques, prob)
                prediction = {
                    "technique_id": tid,
                    "technique_name": technique_info.get("name", "Unknown"),
                    "tactic": technique_info.get("tactic", "Unknown"),
                    "probability": round(prob, 4),
                    "eta_minutes": eta_minutes,
                    "estimated_time": (datetime.utcnow() + timedelta(minutes=eta_minutes)).isoformat(),
                    "targets": self._find_targets_for_technique(tid, critical_targets, environment),
                }
                predictions.append(prediction)

        return predictions

    async def _llm_enhance_predictions(
        self, observations: List[Dict[str, Any]], environment: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        try:
            prompt = f"""Based on these cybersecurity observations, predict the attacker's next likely actions.

Observations: {json.dumps(observations, indent=2)}
Environment: {json.dumps(environment, indent=2)}

Return a JSON array of predictions, each with: technique_id, technique_name, probability (0-1), eta_minutes, targets (list of likely target systems or data).
Consider MITRE ATT&CK framework and common attack chains."""
            result = await llm_manager.generate(prompt)
            result = result.strip()
            if result.startswith("```"):
                result = result.split("\n", 1)[1]
                result = result.rsplit("\n", 1)[0]
            if result.startswith("json"):
                result = result[4:].strip()
            return json.loads(result) if result else []
        except Exception as e:
            logger.warning(f"LLM prediction enhancement failed", error=str(e))
            return []

    def _merge_predictions(self, base: List[Dict], llm: List[Dict]) -> List[Dict]:
        if not llm:
            return base

        technique_map = {p["technique_id"]: p for p in base}
        for lp in llm:
            tid = lp.get("technique_id")
            if tid and tid in technique_map:
                existing = technique_map[tid]
                existing["probability"] = max(existing["probability"], lp.get("probability", 0))
                existing["llm_enhanced"] = True
                if lp.get("targets"):
                    existing["targets"] = list(set(existing.get("targets", []) + lp["targets"]))
            elif tid:
                technique_map[tid] = {
                    "technique_id": tid,
                    "technique_name": lp.get("technique_name", "Unknown"),
                    "tactic": lp.get("tactic", "Unknown"),
                    "probability": lp.get("probability", 0.3),
                    "eta_minutes": lp.get("eta_minutes", 30),
                    "targets": lp.get("targets", []),
                    "llm_enhanced": True,
                }

        return sorted(technique_map.values(), key=lambda x: -x["probability"])[:5]

    def _recommend_defensive_actions(self, predictions: List[Dict], environment: Dict[str, Any]) -> List[Dict]:
        recommendations = []

        tactic_action_map = {
            "lateral_movement": {
                "action": "Enable network segmentation",
                "priority": "high",
                "details": "Isolate critical systems, enforce least-privilege network access",
            },
            "credential_access": {
                "action": "Rotate credentials and enforce MFA",
                "priority": "critical",
                "details": "Reset service account passwords, enforce MFA for all privileged users",
            },
            "exfiltration": {
                "action": "Block outbound data transfers",
                "priority": "critical",
                "details": "Enable DLP rules, monitor large outbound transfers, block unusual egress",
            },
            "impact": {
                "action": "Enable backup isolation and immutable snapshots",
                "priority": "critical",
                "details": "Verify backups, enable immutable storage, prepare IR playbooks",
            },
            "persistence": {
                "action": "Audit and remove unauthorized persistence mechanisms",
                "priority": "high",
                "details": "Check scheduled tasks, startup items, services, WMI persistence",
            },
            "defense_evasion": {
                "action": "Enable enhanced logging and monitoring",
                "priority": "high",
                "details": "Enable Sysmon, PowerShell logging, command line auditing",
            },
            "discovery": {
                "action": "Monitor reconnaissance activities",
                "priority": "medium",
                "details": "Alert on AD enumeration, network scanning, share discovery",
            },
        }

        tactics_seen = set()
        for pred in predictions:
            tactic = pred.get("tactic", "").lower().replace(" ", "_")
            if tactic in tactic_action_map and tactic not in tactics_seen:
                tactics_seen.add(tactic)
                action = tactic_action_map[tactic]
                recommendations.append({
                    "technique_id": pred["technique_id"],
                    "technique_name": pred["technique_name"],
                    "action": action["action"],
                    "priority": action["priority"],
                    "details": action["details"],
                    "timeframe": "immediate" if action["priority"] == "critical" else "within_1_hour",
                })

        return recommendations

    def _analyze_temporal_pattern(self, techniques: List[str]) -> Dict[str, Any]:
        if len(techniques) < 2:
            return {"pattern": "insufficient_data", "estimated_dwell_time_minutes": None}

        tactic_indices = []
        for tid in techniques:
            technique = mitre_mapper.get_technique(tid)
            if technique:
                t = technique.get("tactic", "").lower().replace(" ", "_")
                try:
                    tactic_indices.append(TACTIC_ORDER.index(t))
                except ValueError:
                    pass

        if len(tactic_indices) < 2:
            return {"pattern": "unknown", "estimated_dwell_time_minutes": None}

        dwell_time_per_tactic = 30
        estimated_total = dwell_time_per_tactic * len(tactic_indices)

        if tactic_indices == sorted(tactic_indices):
            pattern = "sequential_progression"
        else:
            pattern = "jump_ahead_or_concurrent"

        return {
            "pattern": pattern,
            "estimated_dwell_time_minutes": estimated_total,
            "estimated_final_stage_time": (datetime.utcnow() + timedelta(minutes=estimated_total)).isoformat(),
        }

    def _infer_targets(self, environment: Dict[str, Any]) -> Dict[str, List[str]]:
        targets = {
            "high_value": environment.get("critical_assets", environment.get("high_value_targets", [])),
            "domain_controllers": environment.get("domain_controllers", []),
            "database_servers": environment.get("database_servers", []),
            "file_servers": environment.get("file_servers", []),
            "ot_systems": environment.get("ot_systems", []),
            "cloud_resources": environment.get("cloud_resources", []),
        }
        return targets

    def _find_targets_for_technique(self, technique_id: str, targets: Dict[str, List[str]], env: Dict) -> List[str]:
        technique = mitre_mapper.get_technique(technique_id)
        if not technique:
            return []

        tactic = technique.get("tactic", "").lower()

        if "lateral_movement" in tactic:
            return targets.get("domain_controllers", []) + targets.get("database_servers", [])
        elif "credential_access" in tactic:
            return targets.get("domain_controllers", [])
        elif "exfiltration" in tactic:
            return targets.get("file_servers", []) + targets.get("database_servers", [])
        elif "impact" in tactic:
            return targets.get("high_value", []) + targets.get("ot_systems", [])
        elif "discovery" in tactic:
            return targets.get("domain_controllers", []) + targets.get("database_servers", [])
        elif "collection" in tactic:
            return targets.get("file_servers", []) + targets.get("cloud_resources", [])

        all_targets = []
        for lst in targets.values():
            all_targets.extend(lst)
        return all_targets[:3]

    def _estimate_eta(self, technique_id: str, current_techniques: List[str], probability: float) -> int:
        technique = mitre_mapper.get_technique(technique_id)
        if not technique:
            return 30

        tactic = technique.get("tactic", "").lower().replace(" ", "_")
        if tactic in {"impact", "exfiltration"}:
            base = 5
        elif tactic in {"lateral_movement", "credential_access"}:
            base = 15
        elif tactic in {"execution", "persistence"}:
            base = 10
        else:
            base = 30

        distance = self._min_technique_distance(current_techniques, technique_id)
        eta = base + (distance * 10)

        prob_factor = 1.0 - (probability * 0.5)
        eta = int(eta * prob_factor)

        return max(eta, 2)

    def _min_technique_distance(self, current_techniques: List[str], target_technique: str) -> int:
        if not current_techniques:
            return 3

        min_dist = 5
        for ct in current_techniques:
            ct_tech = mitre_mapper.get_technique(ct)
            tg_tech = mitre_mapper.get_technique(target_technique)
            if ct_tech and tg_tech:
                ct_tactic = ct_tech.get("tactic", "").lower().replace(" ", "_")
                tg_tactic = tg_tech.get("tactic", "").lower().replace(" ", "_")
                try:
                    dist = abs(TACTIC_ORDER.index(tg_tactic) - TACTIC_ORDER.index(ct_tactic))
                    min_dist = min(min_dist, dist)
                except ValueError:
                    pass

        return min_dist if min_dist < 5 else 3

    def _get_tactic_index(self, tactic: str) -> int:
        tactic_lower = tactic.lower().replace(" ", "_")
        try:
            return TACTIC_ORDER.index(tactic_lower)
        except ValueError:
            return -1

    def _get_predictions(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        prediction_id = input_data.get("prediction_id")
        if prediction_id and prediction_id in self.prediction_history:
            return {"success": True, "prediction": self.prediction_history[prediction_id][-1]}
        entity = input_data.get("entity")
        if entity:
            all_preds = self.prediction_history.get(entity, [])
            return {"success": True, "predictions": all_preds}
        return {"success": True, "all_predictions": dict(self.prediction_history)}

    async def _evaluate_prediction(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        prediction_id = input_data.get("prediction_id")
        actual_outcome = input_data.get("actual_outcome", {})
        if not prediction_id or prediction_id not in self.prediction_history:
            return {"success": False, "error": "Prediction not found"}

        predictions = self.prediction_history[prediction_id]
        actual_technique = actual_outcome.get("technique_id")
        accuracy = 0.0

        for pred in predictions:
            if pred.get("technique_id") == actual_technique:
                accuracy = pred.get("probability", 0)
                break

        return {
            "success": True,
            "prediction_id": prediction_id,
            "accuracy": accuracy,
            "was_correct": accuracy > 0,
        }

    def _generate_prediction_id(self, techniques: List[str]) -> str:
        raw = "_".join(sorted(techniques)) + datetime.utcnow().strftime("%Y%m%d%H%M")
        import hashlib
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def _store_prediction(self, prediction_id: str, result: Dict[str, Any]):
        key = f"pred_{prediction_id}"
        self.prediction_history[key].append(result)
        if len(self.prediction_history[key]) > 10:
            self.prediction_history[key] = self.prediction_history[key][-10:]
