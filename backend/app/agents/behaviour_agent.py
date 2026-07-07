import numpy as np
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app.agents.base_agent import BaseAgent
from app.core.logger import logger
from app.core.database import redis_client


class IsolationForestDetector:
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self._fitted = False

    def fit(self, X: np.ndarray):
        self._fitted = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        scores = np.random.uniform(-0.3, 0.3, size=(X.shape[0],))
        return np.where(scores > 0.5, -1, 1)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return np.random.uniform(0.3, 0.9, size=(X.shape[0],))


class AutoencoderDetector:
    def __init__(self, encoding_dim: int = 16):
        self.encoding_dim = encoding_dim
        self._fitted = False

    def fit(self, X: np.ndarray):
        self._fitted = True

    def get_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        return np.random.uniform(0.01, 0.5, size=(X.shape[0],))


class BehaviourProfile:
    def __init__(self, entity_id: str, entity_type: str):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.login_times: List[int] = []
        self.login_locations: List[str] = []
        self.accessed_resources: Dict[str, int] = defaultdict(int)
        self.used_commands: Dict[str, int] = defaultdict(int)
        self.network_connections: List[Tuple[str, int]] = []
        self.active_hours: List[int] = []
        self.data_transfer_sizes: List[int] = []
        self.weekly_pattern: Dict[int, int] = defaultdict(int)

    def to_vector(self) -> np.ndarray:
        features = []
        features.append(len(self.login_times))
        features.append(len(set(self.login_locations)))
        features.append(len(self.accessed_resources))
        features.append(len(self.used_commands))
        features.append(len(self.network_connections))
        features.append(len(self.active_hours))
        if self.login_times:
            features.append(np.mean(self.login_times))
            features.append(np.std(self.login_times))
        else:
            features.extend([0, 0])
        if self.data_transfer_sizes:
            features.append(np.mean(self.data_transfer_sizes))
            features.append(np.std(self.data_transfer_sizes))
        else:
            features.extend([0, 0])
        return np.array(features, dtype=np.float32)


class BehaviourLearningAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="behaviour_learning_agent",
            agent_type="behaviour_learning",
            version=version,
        )
        self.profiles: Dict[str, BehaviourProfile] = {}
        self.isolation_forest = IsolationForestDetector()
        self.autoencoder = AutoencoderDetector()
        self.entity_types = {"user", "server", "device", "ot", "application"}
        self.baselines: Dict[str, Dict[str, Any]] = {}
        self._feature_cache: Dict[str, np.ndarray] = {}
        self._training_data: Dict[str, List[np.ndarray]] = defaultdict(list)

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "analyze")

        try:
            if action == "train":
                return await self._train(input_data)
            elif action == "analyze":
                return await self._analyze_behavior(input_data)
            elif action == "update_baseline":
                return await self._update_baseline(input_data)
            elif action == "get_profile":
                return await self._get_profile(input_data)
            elif action == "batch_analyze":
                return await self._batch_analyze(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"BehaviourLearningAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _train(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        historical_data = input_data.get("historical_data", [])
        entity_type = input_data.get("entity_type", "user")

        if not historical_data:
            return {"success": False, "error": "No historical data provided"}

        for record in historical_data:
            entity_id = record.get("entity_id")
            if not entity_id:
                continue
            profile = self._get_or_create_profile(entity_id, entity_type)
            self._update_profile_from_record(profile, record)

        X = self._build_training_matrix(entity_type)
        if X.shape[0] > 5:
            self.isolation_forest.fit(X)
            self.autoencoder.fit(X)

        baseline = {
            "entity_type": entity_type,
            "profiles_count": len([p for p in self.profiles.values() if p.entity_type == entity_type]),
            "trained_at": datetime.utcnow().isoformat(),
        }
        self.baselines[entity_type] = baseline

        self.update_metrics(True)
        return {"success": True, "baseline": baseline}

    async def _analyze_behavior(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        entity_id = input_data.get("entity_id")
        entity_type = input_data.get("entity_type", "user")
        events = input_data.get("events", [input_data])

        if not entity_id:
            return {"success": False, "error": "entity_id required"}

        profile = self._get_or_create_profile(entity_id, entity_type)
        for event in events:
            self._update_profile_from_record(profile, event)

        anomalies = []
        for event in events:
            anomaly = self._detect_anomalies(profile, event)
            if anomaly["is_anomalous"]:
                anomalies.append(anomaly)

        anomaly_score = max((a["score"] for a in anomalies), default=0.0)
        overall_risk = self._calculate_risk_score(anomalies)

        result = {
            "success": True,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "anomaly_score": float(anomaly_score),
            "risk_score": float(overall_risk),
            "is_anomalous": anomaly_score > self.confidence_threshold,
            "anomalies": anomalies[:10],
            "profile_summary": {
                "total_events": len(profile.login_times),
                "unique_locations": len(set(profile.login_locations)),
                "unique_resources": len(profile.accessed_resources),
            },
        }

        if anomaly_score > self.confidence_threshold:
            await self.publish_event("behaviour.anomaly", result)

        self.update_metrics(True)
        return result

    async def _update_baseline(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        entity_type = input_data.get("entity_type", "user")
        window_days = input_data.get("window_days", 30)

        relevant_profiles = [p for p in self.profiles.values() if p.entity_type == entity_type]
        if not relevant_profiles:
            return {"success": False, "error": f"No profiles for entity type {entity_type}"}

        X = self._build_training_matrix(entity_type)
        if X.shape[0] > 5:
            self.isolation_forest.fit(X)
            self.autoencoder.fit(X)

        baseline = {
            "entity_type": entity_type,
            "profiles_count": len(relevant_profiles),
            "window_days": window_days,
            "updated_at": datetime.utcnow().isoformat(),
        }
        self.baselines[entity_type] = baseline

        return {"success": True, "baseline": baseline}

    async def _get_profile(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        entity_id = input_data.get("entity_id")
        if not entity_id or entity_id not in self.profiles:
            return {"success": False, "error": "Profile not found"}

        profile = self.profiles[entity_id]
        return {
            "success": True,
            "entity_id": profile.entity_id,
            "entity_type": profile.entity_type,
            "total_logins": len(profile.login_times),
            "unique_locations": list(set(profile.login_locations)),
            "active_hours": list(set(profile.active_hours)),
            "top_commands": dict(sorted(profile.used_commands.items(), key=lambda x: -x[1])[:10]),
            "top_resources": dict(sorted(profile.accessed_resources.items(), key=lambda x: -x[1])[:10]),
        }

    async def _batch_analyze(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        entities = input_data.get("entities", [])
        results = []
        for entity in entities:
            result = await self._analyze_behavior(entity)
            results.append(result)

        high_risk = [r for r in results if r.get("risk_score", 0) > 0.7]
        return {
            "success": True,
            "total_analyzed": len(results),
            "high_risk_count": len(high_risk),
            "results": results,
        }

    def _get_or_create_profile(self, entity_id: str, entity_type: str) -> BehaviourProfile:
        if entity_id not in self.profiles:
            self.profiles[entity_id] = BehaviourProfile(entity_id, entity_type)
        return self.profiles[entity_id]

    def _update_profile_from_record(self, profile: BehaviourProfile, record: Dict[str, Any]):
        if "login_time" in record:
            try:
                t = int(record["login_time"])
                profile.login_times.append(t)
                profile.active_hours.append(t)
            except (ValueError, TypeError):
                pass

        if "location" in record:
            profile.login_locations.append(record["location"])

        if "resource" in record:
            profile.accessed_resources[record["resource"]] += 1

        if "command" in record:
            profile.used_commands[record["command"]] += 1

        if "destination_ip" in record:
            profile.network_connections.append((record["destination_ip"], record.get("port", 0)))

        if "data_size" in record:
            try:
                profile.data_transfer_sizes.append(int(record["data_size"]))
            except (ValueError, TypeError):
                pass

        if "day_of_week" in record:
            try:
                profile.weekly_pattern[int(record["day_of_week"])] += 1
            except (ValueError, TypeError):
                pass

    def _detect_anomalies(self, profile: BehaviourProfile, event: Dict[str, Any]) -> Dict[str, Any]:
        anomalies = []
        score = 0.0
        reasons = []

        if profile.login_times and "login_time" in event:
            hour = event.get("login_time")
            if hour is not None:
                try:
                    hour = int(hour)
                    if profile.active_hours:
                        mean_hour = np.mean(profile.active_hours)
                        std_hour = np.std(profile.active_hours) or 1
                        z_score = abs(hour - mean_hour) / std_hour
                        if z_score > 2.0:
                            anomalies.append(f"Unusual login time: {hour}:00 (z-score: {z_score:.2f})")
                            score += 0.15 * min(z_score / 4.0, 1.0)
                            reasons.append("unusual_login_time")
                except (ValueError, TypeError):
                    pass

        if profile.login_locations and "location" in event:
            location = event.get("location")
            if location and location not in profile.login_locations:
                last_location = profile.login_locations[-1] if profile.login_locations else None
                if last_location and "timestamp" in event:
                    time_diff_minutes = self._estimate_travel_time(last_location, location)
                    event_time = event.get("timestamp", 0)
                    if isinstance(event_time, str):
                        event_time = int(datetime.fromisoformat(event_time).timestamp())
                    if time_diff_minutes > 0 and event_time - time_diff_minutes < 60:
                        anomalies.append(f"Impossible travel: {last_location} -> {location} in < 60min")
                        score += 0.3
                        reasons.append("impossible_travel")

                anomalies.append(f"New login location: {location}")
                score += 0.1
                reasons.append("new_location")

        if "resource" in event:
            resource = event["resource"]
            if profile.accessed_resources and resource not in profile.accessed_resources:
                anomalies.append(f"First-time resource access: {resource}")
                score += 0.1
                reasons.append("new_resource")

            sensitive_patterns = ["\\\\admin$", "\\\\c$", "secret", "confidential", "hr"]
            if any(pattern in resource.lower() for pattern in sensitive_patterns):
                anomalies.append(f"Sensitive resource access: {resource}")
                score += 0.2
                reasons.append("sensitive_access")

        if "command" in event:
            command = event["command"].lower()
            dangerous_commands = ["mimikatz", "pwdump", "secretsdump", "wmic", "reg save",
                                  "vssadmin", "bcdedit", "powershell -enc", "invoke-",
                                  "net user", "net group", "dsquery", "crackmapexec",
                                  "bloodhound", "sharphound", "mssql", "sqlcmd"]
            for dc in dangerous_commands:
                if dc in command:
                    anomalies.append(f"Anomalous command: {command[:100]}")
                    score += 0.25
                    reasons.append(f"dangerous_command:{dc}")
                    break

            powershell_indicators = ["-enc", "-encodedcommand", "frombase64string", "iex",
                                     "invoke-expression", "downloadstring", "webclient"]
            if any(ind in command for ind in powershell_indicators):
                anomalies.append(f"Obfuscated PowerShell usage detected")
                score += 0.2
                reasons.append("obfuscated_powershell")

        if "data_size" in event:
            try:
                size = int(event["data_size"])
                if profile.data_transfer_sizes:
                    mean_size = np.mean(profile.data_transfer_sizes)
                    std_size = np.std(profile.data_transfer_sizes) or 1
                    if size > mean_size + 3 * std_size:
                        anomalies.append(f"Abnormal data transfer: {size} bytes")
                        score += 0.2
                        reasons.append("abnormal_data_transfer")
            except (ValueError, TypeError):
                pass

        if event.get("event_type") in {"logon_failure", "failed_login"}:
            anomalies.append("Failed authentication event")
            score += 0.1
            reasons.append("failed_auth")

        if event.get("event_type") in {"service_install", "service_stop", "service_failure"}:
            anomalies.append(f"Service state change: {event.get('event_type')}")
            score += 0.15
            reasons.append("service_anomaly")

        if event.get("event_type") == "usb_insert":
            anomalies.append("USB device insertion")
            score += 0.1
            reasons.append("usb_insert")

        is_anomalous = score > self.confidence_threshold

        return {
            "is_anomalous": is_anomalous,
            "score": round(min(score, 1.0), 4),
            "anomalies": anomalies[:5],
            "reasons": reasons,
            "event_type": event.get("event_type", "unknown"),
            "entity_id": profile.entity_id,
        }

    def _calculate_risk_score(self, anomalies: List[Dict[str, Any]]) -> float:
        if not anomalies:
            return 0.0
        max_score = max(a["score"] for a in anomalies)
        count_factor = min(len(anomalies) / 10, 1.0)
        return round(min(max_score + (count_factor * 0.2), 1.0), 4)

    def _estimate_travel_time(self, loc1: str, loc2: str) -> int:
        location_distances = {
            ("New York", "London"): 420,
            ("London", "New York"): 420,
            ("New York", "Tokyo"): 720,
            ("Tokyo", "New York"): 720,
            ("London", "Tokyo"): 660,
            ("Tokyo", "London"): 660,
            ("San Francisco", "New York"): 320,
            ("New York", "San Francisco"): 320,
            ("San Francisco", "London"): 540,
            ("London", "San Francisco"): 540,
            ("Singapore", "London"): 720,
            ("London", "Singapore"): 720,
            ("Singapore", "Tokyo"): 420,
            ("Tokyo", "Singapore"): 420,
        }
        return location_distances.get((loc1, loc2), 9999)

    def _build_training_matrix(self, entity_type: str) -> np.ndarray:
        vectors = []
        for profile in self.profiles.values():
            if profile.entity_type == entity_type:
                vectors.append(profile.to_vector())
        if vectors:
            max_len = max(v.shape[0] for v in vectors)
            padded = []
            for v in vectors:
                if v.shape[0] < max_len:
                    v = np.pad(v, (0, max_len - v.shape[0]))
                padded.append(v)
            return np.array(padded)
        return np.empty((0, 4))
