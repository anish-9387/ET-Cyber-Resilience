"""Tests for the behavioural detector's output contract.

These check that the detector produces *well-formed, bounded, deterministic*
output. They deliberately do NOT assert that the detector is accurate - that is
what ``app.evaluation.detection_eval`` measures, and pinning an accuracy figure
in a test would just be the README's marketing claim in a different file.

One test does assert a real behavioural property: scores must not come from a
random number generator. The original ``IsolationForestDetector`` returned
``np.random.uniform(...)`` from ``score_samples``, which would have made every
downstream metric meaningless. The determinism test is what catches a
regression back to that.
"""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pytest

from app.evaluation.datasets import LabeledRecord, generate_benchmark_dataset


@pytest.fixture
def agent():
    from app.agents.behaviour_agent import BehaviourLearningAgent

    return BehaviourLearningAgent()


@pytest.fixture
def trained_agent(agent):
    """An agent with a behavioural baseline built from benign records."""
    dataset = generate_benchmark_dataset(benign_count=600, scenario_repeats=1)
    benign = [r for r in dataset.records if not r.is_malicious][:500]
    for record in benign:
        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, record.to_event())
        agent._record_sample(profile)
    for entity_type in sorted({r.entity_type for r in benign}):
        agent.train_baseline(entity_type, force=True)
    return agent


def _record(**overrides) -> LabeledRecord:
    defaults = dict(
        record_id="t-1",
        entity_id="user.test",
        entity_type="user",
        timestamp=datetime(2026, 6, 1, 3, 0, tzinfo=timezone.utc),
        event_type="logon",
        source="windows",
        description="test event",
    )
    defaults.update(overrides)
    return LabeledRecord(**defaults)


class TestDetectorOutputShape:
    def test_detect_anomalies_returns_expected_keys(self, agent):
        profile = agent._get_or_create_profile("user.test", "user")
        result = agent._detect_anomalies(profile, _record().to_event())

        for key in ("is_anomalous", "score", "anomalies", "reasons", "entity_id"):
            assert key in result, f"missing key {key!r} in detector output"

        assert isinstance(result["is_anomalous"], bool)
        assert isinstance(result["score"], float)
        assert isinstance(result["anomalies"], list)
        assert isinstance(result["reasons"], list)

    def test_score_is_bounded(self, trained_agent):
        """No event, however extreme, may push the score outside [0, 1]."""
        extreme = _record(
            command="mimikatz sekurlsa::logonpasswords && vssadmin delete shadows "
                    "/all && powershell -enc AAAA && net user /domain",
            resource="\\\\srv-dc-01\\c$\\secret\\confidential\\hr",
            data_size=10 ** 12,
            login_time=3,
            location="Unknown-Country",
            event_type="usb_insert",
        )
        profile = trained_agent._get_or_create_profile("user.test", "user")
        result = trained_agent._detect_anomalies(profile, extreme.to_event())
        assert 0.0 <= result["score"] <= 1.0, f"score out of range: {result['score']}"

    def test_is_anomalous_matches_threshold(self, agent):
        profile = agent._get_or_create_profile("user.test", "user")
        result = agent._detect_anomalies(profile, _record(command="mimikatz").to_event())
        assert result["is_anomalous"] == (result["score"] > agent.confidence_threshold)

    def test_empty_event_does_not_crash(self, agent):
        profile = agent._get_or_create_profile("user.test", "user")
        result = agent._detect_anomalies(profile, {})
        assert 0.0 <= result["score"] <= 1.0

    @pytest.mark.parametrize("bad_value", [None, "", "not-a-number", -1, float("nan")])
    def test_malformed_fields_do_not_crash(self, agent, bad_value):
        profile = agent._get_or_create_profile("user.test", "user")
        event = {
            "entity_id": "user.test",
            "event_type": "logon",
            "login_time": bad_value,
            "data_size": bad_value,
        }
        result = agent._detect_anomalies(profile, event)
        assert 0.0 <= result["score"] <= 1.0


class TestDetectorDeterminism:
    """Scores must be a function of the input, not of an RNG."""

    def test_repeated_scoring_is_identical(self, trained_agent):
        record = _record(command="mimikatz sekurlsa::logonpasswords")
        profile = trained_agent._get_or_create_profile("user.test", "user")

        scores = [
            trained_agent._detect_anomalies(profile, record.to_event())["score"]
            for _ in range(10)
        ]
        assert len(set(scores)) == 1, (
            f"detector returned {len(set(scores))} distinct scores for identical "
            f"input: {sorted(set(scores))}. Scores must not be random."
        )

    def test_model_score_is_deterministic(self, trained_agent):
        profile = trained_agent._get_or_create_profile("user.rn.avery", "user")
        results = [trained_agent._model_score(profile) for _ in range(5)]
        if results[0] is None:
            pytest.skip("IsolationForest not fitted for this entity type")
        scores = [r["score"] for r in results]
        assert len(set(scores)) == 1, (
            f"IsolationForest returned varying scores for one profile: {scores}"
        )

    def test_anomaly_detector_is_a_real_sklearn_estimator(self):
        """Guards against a regression to the np.random stub."""
        from sklearn.ensemble import IsolationForest

        from app.ml.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector()
        assert isinstance(detector.isolation_forest, IsolationForest), (
            f"expected sklearn IsolationForest, got "
            f"{type(detector.isolation_forest)}. A stub returning random values "
            "would invalidate every detection metric."
        )

    def test_fitted_forest_separates_outliers(self):
        """A sanity check that the estimator actually learns something."""
        from app.ml.anomaly_detector import AnomalyDetector

        rng = np.random.default_rng(7)
        inliers = rng.normal(0.0, 1.0, size=(300, 4))
        outlier = np.full((1, 4), 50.0)

        detector = AnomalyDetector()
        detector.fit(inliers)

        inlier_decision = detector.isolation_forest.decision_function(inliers).mean()
        outlier_decision = detector.isolation_forest.decision_function(outlier)[0]

        assert outlier_decision < inlier_decision, (
            "a fitted IsolationForest must score a gross outlier as more "
            f"anomalous than typical inliers; got outlier={outlier_decision} "
            f"vs inlier mean={inlier_decision}"
        )


class TestDetectorSignal:
    """Minimal behavioural expectations, kept well below any accuracy claim."""

    def test_known_attack_tooling_outranks_routine_admin_tooling(self, trained_agent):
        profile = trained_agent._get_or_create_profile("user.rn.avery", "user")

        benign = trained_agent._detect_anomalies(
            profile,
            _record(command="schtasks /run /tn NightlyIndex").to_event(),
        )["score"]
        malicious = trained_agent._detect_anomalies(
            profile,
            _record(command="mimikatz sekurlsa::logonpasswords").to_event(),
        )["score"]

        assert malicious > benign, (
            f"credential-dumping tooling scored {malicious}, no higher than a "
            f"routine scheduled task at {benign}"
        )

    def test_dangerous_command_scoring_is_tiered(self, trained_agent):
        """Guards the fix for the defect the xfail above used to document.

        Previously every entry in `dangerous_commands` added a flat +0.25, so
        this test asserted that all four commands scored identically. They must
        now separate: dedicated offensive tooling outranks dual-use LOLBins,
        which outrank routine IT-admin queries.
        """
        profile = trained_agent._get_or_create_profile("user.rn.avery", "user")

        def score(command):
            return trained_agent._detect_anomalies(
                profile, _record(command=command).to_event()
            )["score"]

        offensive = score("mimikatz sekurlsa::logonpasswords")
        dual_use = score("psexec \\\\HOST -s cmd")
        routine = {
            command: score(command)
            for command in (
                "schtasks /run /tn NightlyIndex",
                "net user /domain",
                "wmic product get name",
            )
        }

        assert offensive > dual_use > max(routine.values()), (
            "command risk tiers are not ordered: offensive="
            f"{offensive}, dual_use={dual_use}, routine={routine}"
        )

    def test_dangerous_tooling_outranks_an_innocuous_command(self, trained_agent):
        """The list does at least separate listed tooling from unlisted commands."""
        profile = trained_agent._get_or_create_profile("user.rn.avery", "user")

        innocuous = trained_agent._detect_anomalies(
            profile, _record(command="ipconfig /all").to_event()
        )["score"]
        tooling = trained_agent._detect_anomalies(
            profile, _record(command="mimikatz sekurlsa::logonpasswords").to_event()
        )["score"]

        assert tooling > innocuous, (
            f"credential-dumping tooling ({tooling}) must outrank an innocuous "
            f"command ({innocuous})"
        )

    def test_combine_scores_is_monotone_and_bounded(self, agent):
        """The noisy-OR fusion must never lower a score or leave [0, 1]."""
        for rule_score in (0.0, 0.25, 0.5, 0.75, 1.0):
            for model_value in (0.0, 0.3, 0.7, 1.0):
                fused, path = agent._combine_scores(
                    rule_score, {"score": model_value}
                )
                assert 0.0 <= fused <= 1.0, f"fused score {fused} out of range"
                assert fused >= rule_score - 1e-9, (
                    f"fusion lowered the score: rule={rule_score} -> {fused}"
                )
                assert isinstance(path, str)

    def test_combine_scores_without_model_returns_rule_score(self, agent):
        fused, path = agent._combine_scores(0.42, None)
        assert fused == pytest.approx(0.42)
        assert path == "rules"


class TestAgentProcessContract:
    async def test_analyze_returns_documented_shape(self, agent):
        result = await agent.process({
            "action": "analyze",
            "entity_id": "user.test",
            "entity_type": "user",
            "events": [_record(command="whoami").to_event()],
        })

        assert result["success"] is True
        assert 0.0 <= result["anomaly_score"] <= 1.0
        assert 0.0 <= result["risk_score"] <= 1.0
        assert isinstance(result["is_anomalous"], bool)
        assert isinstance(result["anomalies"], list)

    async def test_analyze_requires_entity_id(self, agent):
        result = await agent.process({"action": "analyze"})
        assert result["success"] is False
        assert "entity_id" in result["error"]

    async def test_unknown_action_is_rejected(self, agent):
        result = await agent.process({"action": "not-a-real-action"})
        assert result["success"] is False
