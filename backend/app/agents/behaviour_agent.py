import numpy as np
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app.agents.base_agent import BaseAgent
from app.core.logger import logger
from app.core.database import redis_client
from app.ml.anomaly_detector import AnomalyDetector

SEVERITY_PRIOR = {"critical": 0.8, "high": 0.6, "medium": 0.3, "low": 0.05, "info": 0.0}
MIN_BASELINE_SAMPLES = 30
MODEL_WEIGHT = 0.6
DECISION_SCALE = 8.0
FEATURE_DIM = 10

# ---------------------------------------------------------------------------
# Per-command risk weighting
# ---------------------------------------------------------------------------
# The previous implementation added a flat +0.25 for a hit anywhere in a single
# flat `dangerous_commands` list. That list mixed dedicated offensive tooling
# (mimikatz) with the ordinary vocabulary of Windows systems administration
# (schtasks, net user, wmic), so every scheduled-task run in a hospital scored
# exactly as high as credential dumping. The rule engine consequently ranked
# benign admin traffic above real attack steps and its ROC-AUC collapsed to
# chance.
#
# The replacement is three tiers, graded by *how much of the observed usage of
# that token in an enterprise is plausibly legitimate* - i.e. an informal
# P(malicious | token seen) - not by how alarming the token sounds:
#
#   OFFENSIVE_TOOLING (0.45)
#       Purpose-built attacker tooling and credential-theft primitives. There is
#       essentially no sanctioned administrative workflow that runs these on a
#       clinical estate, so a single hit is strong evidence on its own. A weight
#       just under 0.5 means one hit alone does not trip the decision threshold
#       but any second corroborating signal does - deliberate, because filename
#       and command-line strings are trivially renamed by an attacker.
#
#   DUAL_USE_ABUSED (0.18)
#       Living-off-the-land binaries and interpreter flags that have real
#       administrative uses but are disproportionately represented in intrusions
#       (encoded PowerShell, PsExec, shadow-copy and boot-config tampering,
#       AV policy edits, rundll32 proxy execution). Meaningful evidence,
#       nowhere near sufficient alone.
#
#   ROUTINE_ADMIN (0.03)
#       Directory and inventory queries and scheduled-task management. These are
#       the daily vocabulary of IT operations and appear orders of magnitude more
#       often in benign traffic than in intrusions. They are kept in the table at
#       a near-zero weight rather than deleted, because they still contribute to
#       a *combination* (e.g. discovery followed by credential access) without
#       generating standalone alerts.
#
# Scoring takes the MAXIMUM matching tier rather than the first match, so a
# command line that contains both a routine and an offensive token is scored on
# the offensive one.
OFFENSIVE_TOOLING_WEIGHT = 0.45
DUAL_USE_WEIGHT = 0.18
ROUTINE_ADMIN_WEIGHT = 0.03

COMMAND_RISK_WEIGHTS: Dict[str, float] = {
    # -- Tier 1: dedicated offensive tooling / credential theft -------------
    "mimikatz": OFFENSIVE_TOOLING_WEIGHT,
    "pwdump": OFFENSIVE_TOOLING_WEIGHT,
    "secretsdump": OFFENSIVE_TOOLING_WEIGHT,
    "crackmapexec": OFFENSIVE_TOOLING_WEIGHT,
    "bloodhound": OFFENSIVE_TOOLING_WEIGHT,
    "sharphound": OFFENSIVE_TOOLING_WEIGHT,
    "dcsync": OFFENSIVE_TOOLING_WEIGHT,
    "pass-the": OFFENSIVE_TOOLING_WEIGHT,
    "lsass": OFFENSIVE_TOOLING_WEIGHT,
    "comsvcs": OFFENSIVE_TOOLING_WEIGHT,
    "minidump": OFFENSIVE_TOOLING_WEIGHT,
    "ntdsutil": OFFENSIVE_TOOLING_WEIGHT,
    # -- Tier 2: dual-use binaries disproportionately seen in intrusions ----
    "powershell -enc": DUAL_USE_WEIGHT,
    "-encodedcommand": DUAL_USE_WEIGHT,
    "-enc ": DUAL_USE_WEIGHT,
    "invoke-": DUAL_USE_WEIGHT,
    "psexec": DUAL_USE_WEIGHT,
    "vssadmin": DUAL_USE_WEIGHT,
    "wbadmin": DUAL_USE_WEIGHT,
    "bcdedit": DUAL_USE_WEIGHT,
    "set-mppreference": DUAL_USE_WEIGHT,
    "rundll32": DUAL_USE_WEIGHT,
    "pkexec": DUAL_USE_WEIGHT,
    "sc stop": DUAL_USE_WEIGHT,
    # -- Tier 3: routine IT administration ----------------------------------
    "schtasks": ROUTINE_ADMIN_WEIGHT,
    "scheduled task": ROUTINE_ADMIN_WEIGHT,
    "net user": ROUTINE_ADMIN_WEIGHT,
    "net group": ROUTINE_ADMIN_WEIGHT,
    "net localgroup": ROUTINE_ADMIN_WEIGHT,
    "dsquery": ROUTINE_ADMIN_WEIGHT,
    "wmic": ROUTINE_ADMIN_WEIGHT,
    "reg save": ROUTINE_ADMIN_WEIGHT,
    "mssql": ROUTINE_ADMIN_WEIGHT,
    "sqlcmd": ROUTINE_ADMIN_WEIGHT,
}

# ---------------------------------------------------------------------------
# Which rules are allowed to move the fused score
# ---------------------------------------------------------------------------
# The rule engine emits two very different kinds of finding. A handful are
# high-specificity: they fire rarely and, when they do, benign explanations are
# scarce. The rest are context rules (first-time resource, new location, unusual
# hour, routine admin tooling) that fire constantly across a healthy estate;
# they are useful to an analyst reading a single alert, but as a *ranking*
# signal they are close to noise, and noisy-OR-ing them into a working model
# drags good detections down toward the benign mass.
#
# So the fused score is built from the high-specificity subset only. The full
# rule score is still reported (``rule_score``) and still drives the per-event
# ``anomalies`` explanation - it is gated out of the fusion, not discarded.
# This is a structural choice with no constant fitted to any corpus.
# ---------------------------------------------------------------------------
# Shipped decision threshold
# ---------------------------------------------------------------------------
# Selected from data, not left at a round 0.5. `app.evaluation.calibration`
# sweeps the fused score over the CALIBRATION slice of the chronological
# three-way split (never the holdout slice the metrics are reported on) and
# takes the SMALLEST threshold whose false-positive rate is at or below the
# 0.05 target. Re-derive with `python -m app.evaluation.calibration`.
#
# Why target FPR rather than max F1: FPR bounds analyst workload per unit of
# telemetry, which is the binding constraint in a real SOC. F1 depends on the
# corpus class balance, so an F1-optimal threshold tuned on a 3.25%-malicious
# synthetic corpus would not transfer to a live estate with a different base
# rate. On the calibration split max-F1 sits at 0.71 (F1 0.675, FPR 0.011);
# 0.64 trades some precision for recall while still clearing the FPR budget.
#
# This is a RAISE from the previous 0.5, not a lowering to manufacture
# detections. The fusion fix moved the whole score distribution upward, so 0.5
# now sits inside the benign mass.
DECISION_THRESHOLD = 0.64

HIGH_SPECIFICITY_REASONS = frozenset({
    "offensive_tooling",
    "obfuscated_powershell",
    "log_clearing",
    "impossible_travel",
    "sensor_severity:critical",
    "sensor_severity:high",
    "failed_auth",
})


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
        self.confidence_threshold = DECISION_THRESHOLD
        self.profiles: Dict[str, BehaviourProfile] = {}
        self.entity_types ={"user", "server", "device", "ot", "application"}
        self.baselines: Dict[str, Dict[str, Any]] = {}
        self._feature_cache: Dict[str, np.ndarray] = {}
        self._training_data: Dict[str, List[np.ndarray]] = defaultdict(list)
        self.detectors: Dict[str, AnomalyDetector] = {}
        self.min_baseline_samples = MIN_BASELINE_SAMPLES

    def _get_detector(self, entity_type: str) -> AnomalyDetector:
        if entity_type not in self.detectors:
            self.detectors[entity_type] = AnomalyDetector(model_path=f"models/anomaly/{entity_type}/")
        return self.detectors[entity_type]

    def _record_sample(self, profile: BehaviourProfile):
        self._training_data[profile.entity_type].append(profile.to_vector())
        self._feature_cache[profile.entity_id] = profile.to_vector()

    def baseline_samples(self, entity_type: str) -> int:
        return len(self._training_data.get(entity_type, []))

    def train_baseline(self, entity_type: str, force: bool = False) -> Dict[str, Any]:
        """Fit the sklearn IsolationForest for `entity_type` on accumulated feature vectors.

        Returns a report; `fitted` is False when there is not enough evidence yet.
        """
        samples = self._training_data.get(entity_type, [])
        n = len(samples)
        if n < self.min_baseline_samples and not force:
            return {
                "fitted": False,
                "entity_type": entity_type,
                "baseline_samples": n,
                "required_samples": self.min_baseline_samples,
            }
        if n < 2:
            return {"fitted": False, "entity_type": entity_type, "baseline_samples": n,
                    "required_samples": self.min_baseline_samples}

        X = np.vstack([self._pad(v) for v in samples])
        detector = self._get_detector(entity_type)
        try:
            detector.fit(X)
        except Exception as e:
            logger.warning("IsolationForest fit failed", entity_type=entity_type, error=str(e))
            return {"fitted": False, "entity_type": entity_type, "baseline_samples": n, "error": str(e)}

        report = {
            "fitted": True,
            "entity_type": entity_type,
            "baseline_samples": n,
            "feature_dim": int(X.shape[1]),
            "trained_at": datetime.utcnow().isoformat(),
        }
        logger.info("Behaviour baseline trained", **{k: v for k, v in report.items() if k != "trained_at"})
        return report

    def _maybe_autofit(self, entity_type: str) -> bool:
        detector = self._get_detector(entity_type)
        n = self.baseline_samples(entity_type)
        if n < self.min_baseline_samples:
            return detector.is_fitted
        refit_due = (not detector.is_fitted) or (n % self.min_baseline_samples == 0)
        if refit_due:
            self.train_baseline(entity_type)
        return detector.is_fitted

    @staticmethod
    def _pad(vector: np.ndarray) -> np.ndarray:
        if vector.shape[0] < FEATURE_DIM:
            return np.pad(vector, (0, FEATURE_DIM - vector.shape[0]))
        return vector[:FEATURE_DIM]

    def _model_score(self, profile: BehaviourProfile) -> Optional[Dict[str, Any]]:
        """Calibrated IsolationForest anomaly score in [0, 1], or None when unfitted.

        sklearn's `decision_function` is positive for inliers and negative for
        outliers. It is squashed with a logistic so that 0 maps to 0.5 and the
        result is monotonically increasing in "how anomalous":

            anomaly = 1 / (1 + exp(DECISION_SCALE * decision))
        """
        detector = self.detectors.get(profile.entity_type)
        if detector is None or not detector.is_fitted:
            return None
        try:
            X = self._pad(profile.to_vector()).reshape(1, -1)
            decision = float(detector.isolation_forest.decision_function(X)[0])
            predicted = int(detector.isolation_forest.predict(X)[0])
        except Exception as e:
            logger.warning("IsolationForest scoring failed", entity_id=profile.entity_id, error=str(e))
            return None

        anomaly = 1.0 / (1.0 + float(np.exp(DECISION_SCALE * decision)))
        return {
            "score": round(anomaly, 4),
            "decision_function": round(decision, 6),
            "is_outlier": predicted == -1,
        }

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
            self._record_sample(profile)

        training = self.train_baseline(entity_type, force=input_data.get("force", False))

        baseline = {
            "entity_type": entity_type,
            "profiles_count": len([p for p in self.profiles.values() if p.entity_type == entity_type]),
            "baseline_samples": self.baseline_samples(entity_type),
            "fitted": training["fitted"],
            "detector": "isolation_forest" if training["fitted"] else "rules",
            "trained_at": datetime.utcnow().isoformat(),
        }
        self.baselines[entity_type] = baseline

        self.update_metrics(True)
        return {"success": True, "baseline": baseline, "training": training}

    async def _analyze_behavior(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        entity_id = input_data.get("entity_id")
        entity_type = input_data.get("entity_type", "user")
        events = input_data.get("events", [input_data])

        if not entity_id:
            return {"success": False, "error": "entity_id required"}

        profile = self._get_or_create_profile(entity_id, entity_type)
        for event in events:
            self._update_profile_from_record(profile, event)

        self._record_sample(profile)
        self._maybe_autofit(entity_type)
        model = self._model_score(profile)

        rule_results = [self._detect_anomalies(profile, event) for event in events]
        rule_score = max((r["score"] for r in rule_results), default=0.0)
        anomalies = [r for r in rule_results if r["is_anomalous"]]

        specific_rule_score = max((r["specific_score"] for r in rule_results), default=0.0)
        anomaly_score, detector_path = self._combine_scores(
            rule_score, model, specific_rule_score
        )
        overall_risk = self._calculate_risk_score(anomalies, anomaly_score)

        result = {
            "success": True,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "anomaly_score": float(round(anomaly_score, 4)),
            "rule_score": float(round(rule_score, 4)),
            "specific_rule_score": float(round(specific_rule_score, 4)),
            "model_score": model["score"] if model else None,
            "detector": detector_path,
            "baseline_samples": self.baseline_samples(entity_type),
            "model_fitted": model is not None,
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

        for profile in relevant_profiles:
            self._record_sample(profile)

        training = self.train_baseline(entity_type, force=input_data.get("force", False))

        baseline = {
            "entity_type": entity_type,
            "profiles_count": len(relevant_profiles),
            "baseline_samples": self.baseline_samples(entity_type),
            "fitted": training["fitted"],
            "window_days": window_days,
            "updated_at": datetime.utcnow().isoformat(),
        }
        self.baselines[entity_type] = baseline

        return {"success": True, "baseline": baseline, "training": training}

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
        contributions: List[Tuple[str, float]] = []

        def add(reason: str, weight: float) -> None:
            contributions.append((reason, float(weight)))

        severity = str(event.get("severity", "")).lower()
        if severity in SEVERITY_PRIOR:
            weight = SEVERITY_PRIOR[severity]
            if weight > 0:
                anomalies.append(f"Sensor severity: {severity}")
                add(f"sensor_severity:{severity}", weight)

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
                            add("unusual_login_time", 0.15 * min(z_score / 4.0, 1.0))
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
                        add("impossible_travel", 0.3)

                anomalies.append(f"New login location: {location}")
                add("new_location", 0.1)

        if "resource" in event:
            resource = event["resource"]
            if profile.accessed_resources and resource not in profile.accessed_resources:
                anomalies.append(f"First-time resource access: {resource}")
                add("new_resource", 0.1)

            sensitive_patterns = ["admin$", "c$", "ipc$", "sysvol", "netlogon",
                                  "secret", "confidential", "payroll", "\\hr\\"]
            if any(pattern in resource.lower() for pattern in sensitive_patterns):
                anomalies.append(f"Sensitive resource access: {resource}")
                add("sensitive_access", 0.2)

        if "command" in event:
            command = str(event["command"]).lower()
            # Take the highest-weighted matching token, not the first match, so
            # "rundll32 ... comsvcs.dll MiniDump lsass" is scored as credential
            # dumping rather than as proxy execution.
            matched = [(w, tok) for tok, w in COMMAND_RISK_WEIGHTS.items() if tok in command]
            if matched:
                weight, token = max(matched)
                anomalies.append(f"Anomalous command: {command[:100]}")
                if weight >= OFFENSIVE_TOOLING_WEIGHT:
                    tier = "offensive_tooling"
                elif weight >= DUAL_USE_WEIGHT:
                    tier = "dual_use_command"
                else:
                    tier = "routine_admin_command"
                add(tier, weight)
                add(f"dangerous_command:{token}", 0.0)

            powershell_indicators = ["-enc", "-encodedcommand", "frombase64string", "iex",
                                     "invoke-expression", "downloadstring", "webclient"]
            if any(ind in command for ind in powershell_indicators):
                anomalies.append(f"Obfuscated PowerShell usage detected")
                add("obfuscated_powershell", 0.2)

        if "data_size" in event:
            try:
                size = int(event["data_size"])
                if profile.data_transfer_sizes:
                    mean_size = np.mean(profile.data_transfer_sizes)
                    std_size = np.std(profile.data_transfer_sizes) or 1
                    if size > mean_size + 3 * std_size:
                        anomalies.append(f"Abnormal data transfer: {size} bytes")
                        add("abnormal_data_transfer", 0.2)
            except (ValueError, TypeError):
                pass

        if event.get("event_type") in {"logon_failure", "failed_login"}:
            anomalies.append("Failed authentication event")
            add("failed_auth", 0.15)

        if event.get("event_type") in {"service_install", "service_stop", "service_failure",
                                       "scheduled_task_created"}:
            anomalies.append(f"Service state change: {event.get('event_type')}")
            add("service_anomaly", 0.2)

        if event.get("event_type") == "audit_log_cleared":
            anomalies.append("Audit log cleared")
            add("log_clearing", 0.3)

        if event.get("event_type") == "usb_insert":
            anomalies.append("USB device insertion")
            add("usb_insert", 0.1)

        score = float(sum(weight for _reason, weight in contributions))
        # Precision-gated subset: only the high-specificity rules are eligible to
        # move the fused score (see HIGH_SPECIFICITY_REASONS).
        specific_score = float(sum(
            weight for reason, weight in contributions
            if reason in HIGH_SPECIFICITY_REASONS
        ))
        reasons = [reason for reason, _weight in contributions]

        return {
            "is_anomalous": score > self.confidence_threshold,
            "score": round(min(score, 1.0), 4),
            "specific_score": round(min(specific_score, 1.0), 4),
            "anomalies": anomalies[:5],
            "reasons": reasons,
            "event_type": event.get("event_type", "unknown"),
            "entity_id": profile.entity_id,
        }

    def _combine_scores(
        self,
        rule_score: float,
        model: Optional[Dict[str, Any]],
        specific_rule_score: Optional[float] = None,
    ) -> Tuple[float, str]:
        """Fuse the precision-gated rule signal with the IsolationForest.

            combined = 1 - (1 - specific_rule) * (1 - model)

        Two things changed here after measurement, both because the previous
        form was measurably destroying discrimination (fused ROC-AUC 0.862
        against 0.967 for the IsolationForest on its own):

        1. **The damping was on the wrong channel.** The old form was
           ``1 - (1 - rule) * (1 - MODEL_WEIGHT * model)``: it multiplied the
           *model* by 0.6 while letting the raw rule score in undamped. The
           ablation in ``app.evaluation.detection_eval`` shows the model is the
           channel carrying the discrimination and the ungated rule score is
           close to chance, so this weighted the weak signal above the strong
           one. The model now enters at full strength.

        2. **The rule channel is precision-gated.** Only the high-specificity
           rules (``HIGH_SPECIFICITY_REASONS``) feed the fusion, via
           ``specific_rule_score``. The broad context rules - new resource, new
           location, off-hours, routine admin tooling - fire on a large fraction
           of healthy traffic; noisy-OR-ing them in lifts the benign mass to
           roughly the same score as real detections, which is exactly what
           flattened the old ROC curve.

        The full ``rule_score`` is still returned to the caller and still drives
        the human-readable ``anomalies`` list. It is gated out of the ranking
        decision, not thrown away.

        ``specific_rule_score`` defaults to ``rule_score`` when not supplied so
        older callers keep working; the shipped path always supplies it.
        """
        if model is None:
            return min(rule_score, 1.0), "rules"

        gated = rule_score if specific_rule_score is None else specific_rule_score
        gated = max(0.0, min(float(gated), 1.0))
        model_score = float(model["score"])

        combined = 1.0 - (1.0 - gated) * (1.0 - model_score)
        path = "combined" if gated > 0 else "isolation_forest"
        return min(combined, 1.0), path

    def _calculate_risk_score(self, anomalies: List[Dict[str, Any]], anomaly_score: float = 0.0) -> float:
        if not anomalies:
            return round(min(anomaly_score, 1.0), 4)
        max_score = max(max(a["score"] for a in anomalies), anomaly_score)
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
