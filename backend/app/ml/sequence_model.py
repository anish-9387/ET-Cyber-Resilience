import numpy as np
from typing import List, Dict, Any, Optional
from collections import defaultdict
from app.core.logger import logger


class AttackSequencePredictor:
    def __init__(self):
        self.transition_matrix = defaultdict(lambda: defaultdict(float))
        self.state_counts = defaultdict(int)
        self.mitre_technique_chains = self._build_mitre_chains()

    def _build_mitre_chains(self) -> Dict[str, List[str]]:
        return {
            "TA0001": ["TA0002", "TA0003"],
            "TA0002": ["TA0003", "TA0004", "TA0006"],
            "TA0003": ["TA0004", "TA0006", "TA0008"],
            "TA0004": ["TA0006", "TA0008", "TA0018"],
            "TA0006": ["TA0008", "TA0016", "TA0040"],
            "TA0008": ["TA0016", "TA0040", "TA0011"],
            "TA0011": ["TA0040"],
            "TA0040": ["TA0040"],
            "initial_access": ["execution", "persistence", "privilege_escalation"],
            "execution": ["persistence", "credential_access", "defense_evasion"],
            "persistence": ["credential_access", "lateral_movement", "defense_evasion"],
            "credential_access": ["lateral_movement", "collection"],
            "lateral_movement": ["collection", "exfiltration", "impact"],
            "collection": ["exfiltration", "impact"],
            "exfiltration": ["impact"],
            "impact": ["impact"]
        }

    def update(self, from_state: str, to_state: str):
        self.transition_matrix[from_state][to_state] += 1.0
        self.state_counts[from_state] += 1

    def predict_next(self, current_state: str, top_k: int = 3) -> List[Dict[str, Any]]:
        predictions = []
        possible_next = self.mitre_technique_chains.get(current_state, [])
        for next_state in possible_next:
            prob = self.transition_matrix[current_state].get(next_state, 0.0)
            if self.state_counts[current_state] > 0:
                prob = max(prob, 1.0 / len(possible_next))
            predictions.append({
                "next_state": next_state,
                "probability": min(prob, 1.0),
                "confidence": 0.7 if prob > 0 else 0.5
            })
        predictions.sort(key=lambda x: x["probability"], reverse=True)
        return predictions[:top_k]

    def predict_with_context(self, sequence: List[str]) -> Dict[str, Any]:
        if not sequence:
            return {"predictions": [], "confidence": 0.0}
        current = sequence[-1]
        predictions = self.predict_next(current)
        chain_confidence = min(0.5 + len(sequence) * 0.1, 0.95)
        return {
            "current_state": current,
            "predictions": predictions,
            "chain_confidence": chain_confidence,
            "sequence_length": len(sequence)
        }
