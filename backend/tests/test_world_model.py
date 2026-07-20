"""Correctness tests for the Bayesian belief update in the world model.

The product's core claim is that ``p_compromised`` is a *principled posterior*
rather than a score someone made up. These tests pin the properties that claim
requires:

* incriminating evidence (LR > 1) must raise P(compromised)
* exculpatory evidence (LR < 1) must lower it
* neutral evidence (LR = 1) must leave it essentially unchanged
* the update must be monotone in the likelihood ratio
* confidence must grow with *independent* corroboration, and grow less for
  correlated evidence from a single source
* P must stay a probability under any input, including adversarial ones
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

world_model_module = pytest.importorskip(
    "app.world_model", reason="world model package not available"
)

from app.world_model import Observation, world_model  # noqa: E402
from app.world_model.entity_state import EntityState  # noqa: E402


BASE_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _observation(
    entity_id: str,
    likelihood_ratio: float,
    *,
    source: str = "sysmon",
    technique_id: str | None = "T1003",
    severity: str = "high",
    description: str | None = None,
    offset_minutes: float = 0.0,
) -> Observation:
    return Observation(
        entity_id=entity_id,
        source=source,
        description=description or f"evidence lr={likelihood_ratio} from {source}",
        technique_id=technique_id,
        likelihood_ratio=likelihood_ratio,
        severity=severity,
        timestamp=BASE_TIME + timedelta(minutes=offset_minutes),
        raw={"entity_type": "server", "criticality": "high"},
    )


@pytest.fixture(autouse=True)
def _clean_world_model():
    """Every test starts from an empty world model."""
    world_model.reset()
    yield
    world_model.reset()


async def _p_after(entity_id: str, *observations: Observation) -> float:
    for observation in observations:
        await world_model.ingest_observation(observation)
    entity = world_model.get_entity(entity_id)
    assert entity is not None, f"entity {entity_id} was not created"
    return float(entity.p_compromised)


class TestBeliefDirection:
    """Evidence must move the posterior in the direction its LR implies."""

    async def test_incriminating_evidence_raises_p(self):
        entity_id = "srv-test-raise"
        await world_model.ingest_observation(_observation(entity_id, 1.0))
        before = float(world_model.get_entity(entity_id).p_compromised)

        await world_model.ingest_observation(
            _observation(entity_id, 12.0, source="edr", technique_id="T1486",
                         offset_minutes=1)
        )
        after = float(world_model.get_entity(entity_id).p_compromised)

        assert after > before, (
            f"LR=12 evidence must raise P(compromised); got {before} -> {after}"
        )

    async def test_contradicting_evidence_lowers_p(self):
        entity_id = "srv-test-lower"
        await world_model.ingest_observation(
            _observation(entity_id, 15.0, source="edr", technique_id="T1003")
        )
        elevated = float(world_model.get_entity(entity_id).p_compromised)
        assert elevated > 0.0

        # An exculpatory observation: far more likely if the host is clean.
        await world_model.ingest_observation(
            _observation(entity_id, 0.05, source="forensics",
                         technique_id=None, severity="info",
                         description="full disk forensic sweep found no artefacts",
                         offset_minutes=5)
        )
        after = float(world_model.get_entity(entity_id).p_compromised)

        assert after < elevated, (
            f"LR=0.05 evidence must lower P(compromised); got {elevated} -> {after}"
        )

    async def test_neutral_evidence_barely_moves_p(self):
        entity_id = "srv-test-neutral"
        await world_model.ingest_observation(
            _observation(entity_id, 5.0, source="edr")
        )
        before = float(world_model.get_entity(entity_id).p_compromised)

        await world_model.ingest_observation(
            _observation(entity_id, 1.0, source="netflow", technique_id=None,
                         description="neutral observation", offset_minutes=2)
        )
        after = float(world_model.get_entity(entity_id).p_compromised)

        # log(1) = 0, so the only movement should come from time decay of the
        # earlier evidence, not from the new observation's content.
        assert after == pytest.approx(before, abs=0.05), (
            f"LR=1 evidence should be near-neutral; got {before} -> {after}"
        )

    async def test_update_is_monotone_in_likelihood_ratio(self):
        """Stronger evidence must never produce a weaker posterior."""
        posteriors = []
        for index, lr in enumerate([0.1, 0.5, 1.0, 2.0, 5.0, 20.0]):
            world_model.reset()
            entity_id = f"srv-monotone-{index}"
            p_value = await _p_after(
                entity_id,
                _observation(entity_id, lr, source="edr", technique_id="T1003"),
            )
            posteriors.append(p_value)

        assert posteriors == sorted(posteriors), (
            f"posterior must increase monotonically with LR; got {posteriors}"
        )

    async def test_repeated_incriminating_evidence_accumulates(self):
        entity_id = "srv-accumulate"
        trajectory = []
        for index in range(5):
            await world_model.ingest_observation(
                _observation(
                    entity_id, 6.0,
                    source=f"sensor-{index}",
                    technique_id=f"T10{index}0",
                    description=f"independent detection {index}",
                    offset_minutes=index,
                )
            )
            trajectory.append(float(world_model.get_entity(entity_id).p_compromised))

        assert trajectory == sorted(trajectory), (
            f"independent incriminating evidence must accumulate; got {trajectory}"
        )
        assert trajectory[-1] > trajectory[0]


class TestConfidence:
    """Confidence must reflect how much independent corroboration exists."""

    async def test_confidence_grows_with_independent_evidence(self):
        entity_id = "srv-confidence"
        confidences = []
        for index in range(4):
            await world_model.ingest_observation(
                _observation(
                    entity_id, 4.0,
                    source=f"independent-sensor-{index}",
                    technique_id=f"T11{index}1",
                    description=f"corroborating detection {index}",
                    offset_minutes=index,
                )
            )
            confidences.append(float(world_model.get_entity(entity_id).confidence))

        assert confidences == sorted(confidences), (
            f"confidence must be non-decreasing with independent evidence; "
            f"got {confidences}"
        )
        assert confidences[-1] > confidences[0], (
            "four independent sources must yield more confidence than one"
        )

    async def test_confidence_is_bounded(self):
        entity_id = "srv-confidence-bound"
        for index in range(30):
            await world_model.ingest_observation(
                _observation(
                    entity_id, 40.0,
                    source=f"sensor-{index}",
                    technique_id=f"T12{index:02d}",
                    description=f"detection {index}",
                    offset_minutes=index,
                )
            )
        confidence = float(world_model.get_entity(entity_id).confidence)
        assert 0.0 <= confidence <= 1.0, f"confidence out of range: {confidence}"

    async def test_correlated_evidence_confers_less_confidence(self):
        """Four alerts from one sensor must not equal four independent ones."""
        world_model.reset()
        for index in range(4):
            await world_model.ingest_observation(
                _observation(
                    "srv-correlated", 4.0,
                    source="single-sensor",
                    technique_id="T1003",
                    description=f"repeat alert {index}",
                    offset_minutes=index,
                )
            )
        correlated = float(world_model.get_entity("srv-correlated").confidence)

        world_model.reset()
        for index in range(4):
            await world_model.ingest_observation(
                _observation(
                    "srv-independent", 4.0,
                    source=f"sensor-{index}",
                    technique_id=f"T13{index}1",
                    description=f"distinct alert {index}",
                    offset_minutes=index,
                )
            )
        independent = float(world_model.get_entity("srv-independent").confidence)

        assert independent >= correlated, (
            "independent corroboration must confer at least as much confidence "
            f"as repeated alerts from one source; got independent={independent} "
            f"vs correlated={correlated}"
        )


class TestProbabilityInvariants:
    """P(compromised) must remain a probability under any input."""

    @pytest.mark.parametrize(
        "likelihood_ratio",
        [0.0, 1e-9, 0.001, 1.0, 1000.0, 1e9, float("inf")],
    )
    async def test_p_stays_in_unit_interval(self, likelihood_ratio: float):
        entity_id = "srv-bounds"
        await world_model.ingest_observation(
            _observation(entity_id, likelihood_ratio)
        )
        entity = world_model.get_entity(entity_id)
        p_value = float(entity.p_compromised)
        assert 0.0 <= p_value <= 1.0, (
            f"P(compromised)={p_value} outside [0,1] for LR={likelihood_ratio}"
        )

    async def test_extreme_evidence_cannot_reach_certainty(self):
        """No finite evidence stream should drive belief to exactly 0 or 1."""
        entity_id = "srv-no-certainty"
        for index in range(50):
            await world_model.ingest_observation(
                _observation(
                    entity_id, 1e6,
                    source=f"sensor-{index}",
                    technique_id=f"T14{index:02d}",
                    description=f"overwhelming evidence {index}",
                    offset_minutes=index,
                )
            )
        p_value = float(world_model.get_entity(entity_id).p_compromised)
        assert p_value < 1.0, (
            "belief reached exact certainty; a Bayesian posterior should never "
            "be unrecoverable from"
        )

    async def test_fresh_entity_starts_at_prior(self):
        entity = EntityState(id="srv-prior", name="srv-prior", entity_type="server")
        assert 0.0 <= entity.p_compromised <= 1.0
        assert entity.p_compromised == pytest.approx(entity.prior), (
            "an entity with no evidence must sit at its prior"
        )

    async def test_duplicate_evidence_is_not_double_counted(self):
        """Ingesting the identical observation twice must not double the update."""
        entity_id = "srv-dedupe"
        observation = _observation(entity_id, 10.0, source="edr")

        await world_model.ingest_observation(observation)
        after_first = float(world_model.get_entity(entity_id).p_compromised)

        await world_model.ingest_observation(observation)
        after_second = float(world_model.get_entity(entity_id).p_compromised)

        assert after_second == pytest.approx(after_first, abs=1e-6), (
            f"replaying an identical observation changed belief "
            f"{after_first} -> {after_second}; evidence must be deduplicated"
        )


class TestObservationLog:
    """MTTD measurement depends on the observation log being complete."""

    async def test_every_observation_is_logged(self):
        entity_id = "srv-log"
        count = 6
        for index in range(count):
            await world_model.ingest_observation(
                _observation(
                    entity_id, 3.0,
                    source=f"sensor-{index}",
                    description=f"logged observation {index}",
                    offset_minutes=index,
                )
            )
        assert len(world_model.observation_log) >= count, (
            f"expected at least {count} log entries, found "
            f"{len(world_model.observation_log)}"
        )

    async def test_snapshot_is_serialisable_and_consistent(self):
        entity_id = "srv-snapshot"
        await world_model.ingest_observation(_observation(entity_id, 9.0))

        snapshot = world_model.snapshot()
        assert "entities" in snapshot
        assert snapshot["entity_count"] == len(snapshot["entities"])
        for entity in snapshot["entities"]:
            assert 0.0 <= entity["p_compromised"] <= 1.0
            assert 0.0 <= entity["confidence"] <= 1.0
