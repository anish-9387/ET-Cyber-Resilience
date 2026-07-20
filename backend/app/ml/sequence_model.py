from typing import List, Dict, Any, Optional, Iterable, Tuple
from collections import defaultdict
from app.core.logger import logger


class AttackSequencePredictor:
    """First-order Markov model over attack states (tactics or MITRE technique ids).

    Transition probabilities are Laplace-smoothed maximum-likelihood estimates:

        P(next | cur) = (count(cur -> next) + alpha) / (total(cur) + alpha * |V(cur)|)

    where V(cur) is the support for `cur`: every successor observed during `fit`
    plus every successor declared in the structural prior (`mitre_technique_chains`).
    An unobserved-but-plausible successor therefore gets a small non-zero mass
    instead of the old uniform 1/len(possible_next) placeholder.
    """

    def __init__(self, alpha: float = 0.5):
        self.alpha = alpha
        self.transition_counts: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.state_counts: Dict[str, float] = defaultdict(float)
        self.mitre_technique_chains = self._build_mitre_chains()
        self.observed_sequences: int = 0

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
            "privilege_escalation": ["credential_access", "defense_evasion", "discovery"],
            "defense_evasion": ["credential_access", "discovery", "lateral_movement"],
            "credential_access": ["lateral_movement", "discovery", "collection"],
            "discovery": ["lateral_movement", "collection"],
            "lateral_movement": ["collection", "exfiltration", "impact"],
            "collection": ["exfiltration", "impact"],
            "command_and_control": ["collection", "exfiltration", "impact"],
            "exfiltration": ["impact"],
            "impact": ["impact"],
        }

    def support(self, state: str) -> List[str]:
        candidates = set(self.mitre_technique_chains.get(state, []))
        candidates.update(self.transition_counts.get(state, {}).keys())
        return sorted(candidates)

    def update(self, from_state: str, to_state: str, weight: float = 1.0):
        self.transition_counts[from_state][to_state] += weight
        self.state_counts[from_state] += weight

    def fit(self, sequences: Iterable[List[str]], weight: float = 1.0) -> Dict[str, Any]:
        count = 0
        for sequence in sequences:
            states = [s for s in sequence if s]
            if len(states) < 2:
                continue
            for cur, nxt in zip(states, states[1:]):
                self.update(cur, nxt, weight)
            count += 1
        self.observed_sequences += count
        logger.info(
            "AttackSequencePredictor fitted",
            sequences=count,
            states=len(self.state_counts),
            total_sequences=self.observed_sequences,
        )
        return {"sequences_fitted": count, "states": len(self.state_counts)}

    def transition_probability(self, from_state: str, to_state: str) -> float:
        support = self.support(from_state)
        if to_state not in support:
            support = support + [to_state]
        total = self.state_counts.get(from_state, 0.0)
        count = self.transition_counts.get(from_state, {}).get(to_state, 0.0)
        denom = total + self.alpha * len(support)
        if denom <= 0:
            return 0.0
        return (count + self.alpha) / denom

    def predict_next(self, current_state: str, top_k: int = 3) -> List[Dict[str, Any]]:
        support = self.support(current_state)
        if not support:
            return []

        total = self.state_counts.get(current_state, 0.0)
        evidence_confidence = total / (total + 5.0)

        predictions = []
        for next_state in support:
            prob = self.transition_probability(current_state, next_state)
            observed = self.transition_counts.get(current_state, {}).get(next_state, 0.0)
            predictions.append({
                "next_state": next_state,
                "probability": round(min(prob, 1.0), 4),
                "observed_count": observed,
                "confidence": round(0.4 + 0.55 * evidence_confidence, 4),
            })

        predictions.sort(key=lambda x: (x["probability"], x["observed_count"]), reverse=True)
        return predictions[:top_k]

    def predict_with_context(self, sequence: List[str]) -> Dict[str, Any]:
        if not sequence:
            return {"predictions": [], "confidence": 0.0, "chain_confidence": 0.0}
        current = sequence[-1]
        predictions = self.predict_next(current)
        observed_mass = sum(
            self.transition_counts.get(cur, {}).get(nxt, 0.0)
            for cur, nxt in zip(sequence, sequence[1:])
        )
        chain_confidence = min(0.4 + 0.1 * len(sequence) + 0.02 * observed_mass, 0.95)
        return {
            "current_state": current,
            "predictions": predictions,
            "chain_confidence": round(chain_confidence, 4),
            "sequence_length": len(sequence),
            "observed_sequences": self.observed_sequences,
        }

    def stats(self) -> Dict[str, Any]:
        return {
            "alpha": self.alpha,
            "states": len(self.state_counts),
            "transitions": sum(len(v) for v in self.transition_counts.values()),
            "observed_sequences": self.observed_sequences,
            "total_mass": sum(self.state_counts.values()),
        }


def _load_attack_chain_sequences() -> List[List[str]]:
    try:
        from app.agents.attack_story_builder import ATTACK_CHAINS
    except Exception as e:
        logger.warning("Could not seed sequence model from ATTACK_CHAINS", error=str(e))
        return []

    sequences: List[List[str]] = []
    for chain in ATTACK_CHAINS:
        steps = chain.get("steps") or []
        if len(steps) >= 2:
            sequences.append(list(steps))
        techniques = chain.get("common_techniques") or []
        if len(techniques) >= 2:
            sequences.append(list(techniques))
    return sequences


def build_seeded_predictor(alpha: float = 0.5) -> AttackSequencePredictor:
    predictor = AttackSequencePredictor(alpha=alpha)
    sequences = _load_attack_chain_sequences()
    if sequences:
        predictor.fit(sequences)
    return predictor


sequence_predictor = build_seeded_predictor()
