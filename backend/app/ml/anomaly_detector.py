import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any, Optional
import pickle
import os
from app.core.logger import logger


class AnomalyDetector:
    def __init__(self, model_path: str = "models/anomaly/"):
        self.model_path = model_path
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        self.autoencoder = None
        self.is_fitted = False

    def fit(self, data: np.ndarray):
        self.isolation_forest.fit(data)
        self.is_fitted = True
        logger.info("Anomaly detector trained on %d samples", len(data))

    def predict(self, data: np.ndarray) -> List[float]:
        if not self.is_fitted:
            return [0.0] * len(data)
        scores = self.isolation_forest.score_samples(data)
        anomalies = self.isolation_forest.predict(data)
        results = []
        for score, anomaly in zip(scores, anomalies):
            normalized_score = 1.0 / (1.0 + np.exp(-score))
            is_anomaly = bool(anomaly == -1)
            results.append({
                "anomaly_score": float(normalized_score),
                "is_anomaly": is_anomaly,
                "confidence": float(abs(normalized_score - 0.5) * 2)
            })
        return results

    def save(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path: str):
        with open(path, "rb") as f:
            return pickle.load(f)


class BehaviourBaseline:
    def __init__(self):
        self.user_profiles: Dict[str, Dict] = {}
        self.server_profiles: Dict[str, Dict] = {}
        self.network_profiles: Dict[str, Dict] = {}

    def add_user_event(self, user_id: str, event: Dict[str, Any]):
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                "login_times": [],
                "ips": [],
                "locations": [],
                "applications": [],
                "devices": [],
                "data_volumes": [],
                "protocols": []
            }
        profile = self.user_profiles[user_id]
        profile["login_times"].append(event.get("timestamp"))
        profile["ips"].append(event.get("ip"))
        profile["locations"].append(event.get("location"))
        profile["applications"].append(event.get("application"))
        profile["devices"].append(event.get("device"))
        profile["data_volumes"].append(event.get("data_volume", 0))
        profile["protocols"].append(event.get("protocol"))

    def detect_anomaly(self, user_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        if user_id not in self.user_profiles:
            return {"anomaly_score": 0.3, "reason": "New user - insufficient baseline", "confidence": 0.3}

        profile = self.user_profiles[user_id]
        anomalies = []
        score = 0.0

        if profile["login_times"]:
            from datetime import datetime
            usual_hours = [datetime.fromisoformat(t).hour for t in profile["login_times"][-30:]]
            event_hour = datetime.fromisoformat(event.get("timestamp", "")).hour if event.get("timestamp") else 0
            if usual_hours and event_hour not in usual_hours:
                anomalies.append("Unusual login time")
                score += 0.3

        if profile["locations"]:
            if event.get("location") and event["location"] not in profile["locations"][-20:]:
                anomalies.append("New location")
                score += 0.2

        if profile["applications"]:
            if event.get("application") and event["application"] not in profile["applications"][-50:]:
                anomalies.append(f"Unusual application: {event['application']}")
                score += 0.25

        if event.get("powershell") or event.get("command_line"):
            anomalies.append("Command line activity")
            score += 0.15

        return {
            "anomaly_score": min(score, 1.0),
            "anomalies": anomalies,
            "confidence": min(score + 0.2, 1.0),
            "is_anomaly": score > 0.5
        }
