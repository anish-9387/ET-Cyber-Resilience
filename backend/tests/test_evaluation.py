"""Tests for the evaluation harness and the audit trail.

Two jobs:

1. **Metric integrity.** Every rate must be in [0, 1] and must be *internally
   consistent* - precision recomputed from TP/FP must equal reported precision,
   the confusion matrix must sum to the sample count, and so on. A metric that
   looks plausible but is not derivable from its own confusion matrix is a bug
   that these tests are designed to catch.

2. **Auditability** (judged criterion 5). Every automated decision must leave an
   audit record, and the trail must be tamper-evident.

The tests assert *properties*, never specific accuracy values. Pinning "recall
must be >= 0.8" would recreate exactly the unfounded claim this package exists
to replace.
"""

from __future__ import annotations

import math

import pytest

from app.evaluation.attribution_eval import evaluate_attribution
from app.evaluation.datasets import (
    DEFAULT_SEED,
    generate_benchmark_dataset,
    load_external_dataset,
)
from app.evaluation.detection_eval import evaluate_detection
from app.evaluation.response_eval import evaluate_response_coverage


@pytest.fixture(scope="module")
def dataset():
    return generate_benchmark_dataset(benign_count=1200, scenario_repeats=2)


@pytest.fixture(scope="module")
def detection(dataset):
    return evaluate_detection(dataset=dataset)


@pytest.fixture(scope="module")
def attribution(dataset):
    return evaluate_attribution(dataset=dataset)


@pytest.fixture(scope="module")
def response():
    return evaluate_response_coverage()


def _is_rate(value) -> bool:
    return value is None or (
        isinstance(value, (int, float))
        and not math.isnan(value)
        and 0.0 <= value <= 1.0
    )


class TestDatasetGeneration:
    def test_is_reproducible_for_a_fixed_seed(self):
        first = generate_benchmark_dataset(benign_count=400, scenario_repeats=1)
        second = generate_benchmark_dataset(benign_count=400, scenario_repeats=1)

        assert len(first) == len(second)
        assert [r.record_id for r in first.records] == [
            r.record_id for r in second.records
        ]
        assert [r.is_malicious for r in first.records] == [
            r.is_malicious for r in second.records
        ]

    def test_different_seeds_give_different_corpora(self):
        first = generate_benchmark_dataset(seed=1, benign_count=400, scenario_repeats=1)
        second = generate_benchmark_dataset(seed=2, benign_count=400, scenario_repeats=1)
        assert [r.entity_id for r in first.records] != [
            r.entity_id for r in second.records
        ]

    def test_class_imbalance_is_realistic(self, dataset):
        """Security telemetry is overwhelmingly benign; the corpus must reflect it."""
        assert 0.001 < dataset.malicious_rate < 0.20, (
            f"malicious rate {dataset.malicious_rate} is not a realistic class "
            "balance for security telemetry"
        )

    def test_provenance_declares_synthetic_and_seed(self, dataset):
        provenance = dataset.provenance
        assert provenance["is_synthetic"] is True, (
            "the default corpus is synthetic and must say so"
        )
        assert provenance["seed"] == DEFAULT_SEED
        assert "synthetic_disclaimer" in provenance

    def test_every_record_carries_a_label(self, dataset):
        for record in dataset.records:
            assert isinstance(record.is_malicious, bool)
            if record.is_malicious:
                assert record.scenario_id is not None

    def test_train_split_excludes_malicious_records(self, dataset):
        train, evaluate = dataset.split_by_time()
        assert train, "training split is empty"
        assert not any(r.is_malicious for r in train), (
            "baseline training data must be benign-only or the measured recall "
            "is inflated by label leakage"
        )
        assert any(r.is_malicious for r in evaluate), (
            "evaluation split contains no malicious records to detect"
        )

    def test_split_is_chronological(self, dataset):
        train, evaluate = dataset.split_by_time()
        if train and evaluate:
            assert max(r.timestamp for r in train) <= max(
                r.timestamp for r in evaluate
            )

    def test_external_loader_does_not_invent_data(self, tmp_path):
        csv_path = tmp_path / "fake_cicids.csv"
        csv_path.write_text(
            "Destination Port,Label\n80,BENIGN\n443,DoS Hulk\n22,BENIGN\n",
            encoding="utf-8",
        )
        loaded = load_external_dataset(csv_path)

        assert len(loaded) == 3
        assert [r.is_malicious for r in loaded.records] == [False, True, False]
        assert loaded.provenance["is_synthetic"] is False
        assert all(r.true_technique is None for r in loaded.records), (
            "CICIDS2017 ships no ATT&CK labels; the loader must not fabricate them"
        )
        assert loaded.provenance["attribution_scorable"] is False

    def test_external_loader_rejects_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_external_dataset(tmp_path / "nope.csv")


class TestDetectionMetrics:
    def test_all_rates_are_in_unit_interval(self, detection):
        for key in ("precision", "recall", "f1", "fpr", "roc_auc", "accuracy",
                    "specificity", "average_precision"):
            assert _is_rate(detection[key]), (
                f"{key}={detection[key]} is not a valid rate in [0,1]"
            )

    def test_confusion_matrix_sums_to_sample_count(self, detection):
        total = detection["tp"] + detection["fp"] + detection["tn"] + detection["fn"]
        assert total == detection["samples"], (
            f"confusion matrix sums to {total} but samples={detection['samples']}"
        )

    def test_counts_are_non_negative_integers(self, detection):
        for key in ("tp", "fp", "tn", "fn", "samples"):
            assert isinstance(detection[key], int) and detection[key] >= 0

    def test_precision_matches_its_confusion_matrix(self, detection):
        tp, fp = detection["tp"], detection["fp"]
        expected = tp / (tp + fp) if (tp + fp) else 0.0
        assert detection["precision"] == pytest.approx(expected, abs=1e-4), (
            f"reported precision {detection['precision']} != TP/(TP+FP) = {expected}"
        )

    def test_recall_matches_its_confusion_matrix(self, detection):
        tp, fn = detection["tp"], detection["fn"]
        expected = tp / (tp + fn) if (tp + fn) else 0.0
        assert detection["recall"] == pytest.approx(expected, abs=1e-4), (
            f"reported recall {detection['recall']} != TP/(TP+FN) = {expected}"
        )

    def test_fpr_matches_its_confusion_matrix(self, detection):
        fp, tn = detection["fp"], detection["tn"]
        expected = fp / (fp + tn) if (fp + tn) else 0.0
        assert detection["fpr"] == pytest.approx(expected, abs=1e-4)

    def test_f1_is_the_harmonic_mean(self, detection):
        precision, recall = detection["precision"], detection["recall"]
        expected = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) else 0.0
        )
        assert detection["f1"] == pytest.approx(expected, abs=1e-3)

    def test_positives_match_ground_truth(self, detection):
        assert detection["tp"] + detection["fn"] == detection["positives_in_eval_split"]
        assert detection["fp"] + detection["tn"] == detection["negatives_in_eval_split"]

    def test_threshold_sweep_is_internally_consistent(self, detection):
        sweep = detection["threshold_sweep"]
        assert sweep, "threshold sweep is empty"
        for row in sweep:
            total = row["tp"] + row["fp"] + row["tn"] + row["fn"]
            assert total == detection["samples"]
            for key in ("precision", "recall", "f1", "fpr"):
                assert _is_rate(row[key]), f"sweep {key}={row[key]} out of range"

    def test_recall_is_monotone_non_increasing_across_thresholds(self, detection):
        """Raising the bar can only ever catch fewer positives."""
        sweep = sorted(detection["threshold_sweep"], key=lambda r: r["threshold"])
        recalls = [row["recall"] for row in sweep]
        for earlier, later in zip(recalls, recalls[1:]):
            assert later <= earlier + 1e-9, (
                f"recall increased with a higher threshold: {recalls}"
            )

    def test_fpr_is_monotone_non_increasing_across_thresholds(self, detection):
        sweep = sorted(detection["threshold_sweep"], key=lambda r: r["threshold"])
        fprs = [row["fpr"] for row in sweep]
        for earlier, later in zip(fprs, fprs[1:]):
            assert later <= earlier + 1e-9, (
                f"FPR increased with a higher threshold: {fprs}"
            )

    def test_reports_synthetic_provenance(self, detection):
        assert detection["provenance"]["is_synthetic"] is True
        assert any("synthetic" in c.lower() for c in detection["caveats"]), (
            "a synthetic-corpus result must carry a synthetic-data caveat"
        )

    def test_does_not_claim_unverifiable_fp_reduction(self, detection):
        """The README's '90% false-positive reduction' has no baseline."""
        check = detection["readme_claim_check"]
        assert check["false_positive_reduction_measurable"] is False, (
            "a false-positive REDUCTION requires a pre-Sentinel baseline that "
            "does not exist in this repo; it must not be reported as measured"
        )


class TestAttributionMetrics:
    def test_accuracies_are_in_unit_interval(self, attribution):
        for key in ("technique_accuracy", "tactic_accuracy",
                    "base_technique_accuracy", "unmapped_rate"):
            assert _is_rate(attribution[key]), f"{key}={attribution[key]} invalid"

    def test_exact_accuracy_never_exceeds_base_accuracy(self, attribution):
        """An exact match is strictly stronger than a base-technique match."""
        assert attribution["technique_accuracy"] <= (
            attribution["base_technique_accuracy"] + 1e-9
        )

    def test_match_counts_are_consistent_with_support(self, attribution):
        total = attribution["scorable_records"]
        assert attribution["exact_technique_matches"] <= total
        assert attribution["base_technique_matches"] <= total
        assert attribution["tactic_matches"] <= total
        assert attribution["unmapped_events"] <= total

    def test_per_technique_support_sums_to_total(self, attribution):
        support = sum(row["support"] for row in attribution["per_technique"])
        assert support == attribution["scorable_records"]

    def test_per_technique_rates_are_valid(self, attribution):
        for row in attribution["per_technique"]:
            for key in ("exact_accuracy", "base_technique_accuracy",
                        "tactic_accuracy"):
                assert _is_rate(row[key]), f"{row['true_technique']} {key} invalid"

    def test_confusion_summary_totals_match(self, attribution):
        total = sum(row["count"] for row in attribution["confusion_summary"])
        assert total == attribution["scorable_records"]

    def test_coverage_limitation_is_reported(self, attribution):
        """Honesty about the ceiling is part of the deliverable."""
        coverage = attribution["coverage"]
        assert "/" in attribution["technique_coverage"]
        assert coverage["mapper_technique_count"] > 0
        assert coverage["mapper_technique_count"] < coverage["attack_enterprise_total"]
        assert coverage["coverage_fraction_of_total"] < 1.0
        assert coverage["attack_reference_is_external"] is True
        assert "ceiling_note" in coverage

    def test_constant_confidence_is_reported(self, attribution):
        """map_event returns a hardcoded 0.85 and the payload must say so."""
        confidence = attribution["confidence_reporting"]
        assert confidence["confidence_is_constant"] is True
        assert confidence["constant_value"] == pytest.approx(0.85)
        assert any(
            "confidence" in c.lower() for c in attribution["caveats"]
        ), "the constant-confidence limitation must appear in the caveats"


class TestResponseCoverage:
    def test_counts_are_consistent(self, response):
        assert response["automatable"] <= response["total_steps"]
        assert response["steps_automatable_by_policy"] == response["automatable"]
        assert 0.0 <= response["coverage_pct"] <= 100.0

    def test_coverage_pct_matches_its_counts(self, response):
        expected = 100 * response["automatable"] / response["total_steps"]
        assert response["coverage_pct"] == pytest.approx(expected, abs=0.01)

    def test_per_playbook_steps_sum_to_total(self, response):
        total = sum(p["total_steps"] for p in response["per_playbook"])
        automatable = sum(
            p["steps_automatable_by_policy"] for p in response["per_playbook"]
        )
        assert total == response["total_steps"]
        assert automatable == response["automatable"]

    def test_execution_mode_is_declared(self, response):
        assert response["execution_mode"] in {"simulated", "live"}

    def test_real_integration_count_is_honest(self, response):
        """No firewall/AD/EDR/hypervisor client exists, so this must be 0."""
        assert response["steps_with_real_integration"] == 0, (
            "no real containment integration exists in this build; a non-zero "
            "count here would misrepresent capability"
        )
        assert response["effective_autonomous_containment_pct"] == 0.0
        assert response["execution_mode"] == "simulated"

    def test_policy_and_capability_are_not_conflated(self, response):
        """The two numbers must be reported separately, and they differ."""
        assert "steps_automatable_by_policy" in response
        assert "steps_with_real_integration" in response
        assert response["steps_automatable_by_policy"] > response[
            "steps_with_real_integration"
        ], "policy headroom must not be presented as demonstrated capability"

    def test_simulation_caveat_is_present(self, response):
        assert any(
            "simulated" in c.lower() for c in response["caveats"]
        ), "the simulated-execution caveat must be present"

    def test_approval_gated_playbooks_have_zero_coverage(self, response):
        for playbook in response["per_playbook"]:
            if playbook["blocks_on_human_approval"]:
                assert playbook["steps_automatable_by_policy"] == 0, (
                    f"{playbook['playbook']} gates on human approval but reports "
                    "automatable steps"
                )


class TestAuditability:
    """Judged criterion 5: every automated action must be auditable."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        pytest.importorskip("app.world_model")
        from app.world_model import world_model
        from app.world_model.audit import audit

        world_model.reset()
        audit.reset()
        yield
        world_model.reset()
        audit.reset()

    async def test_belief_update_writes_an_audit_record(self):
        from datetime import datetime, timezone

        from app.world_model import Observation, world_model
        from app.world_model.audit import audit

        before = len(audit.all_records())
        await world_model.ingest_observation(Observation(
            entity_id="srv-audit-1",
            source="edr",
            description="credential dumping detected",
            technique_id="T1003",
            likelihood_ratio=9.0,
            severity="high",
            timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
            raw={"entity_type": "server"},
        ))
        after = audit.all_records()

        assert len(after) > before, (
            "an automated belief update produced no audit record"
        )

    async def test_every_belief_update_is_audited(self):
        from datetime import datetime, timedelta, timezone

        from app.world_model import Observation, world_model
        from app.world_model.audit import audit

        count = 5
        base = datetime(2026, 6, 1, tzinfo=timezone.utc)
        for index in range(count):
            await world_model.ingest_observation(Observation(
                entity_id=f"srv-audit-{index}",
                source=f"sensor-{index}",
                description=f"automated detection {index}",
                technique_id="T1021",
                likelihood_ratio=7.0,
                severity="high",
                timestamp=base + timedelta(minutes=index),
                raw={"entity_type": "server"},
            ))

        records = audit.all_records()
        assert len(records) >= count, (
            f"{count} automated decisions produced only {len(records)} audit "
            "records; the trail is incomplete"
        )

    async def test_audit_records_carry_reasoning_and_evidence(self):
        from datetime import datetime, timezone

        from app.world_model import Observation, world_model
        from app.world_model.audit import audit

        await world_model.ingest_observation(Observation(
            entity_id="srv-audit-detail",
            source="edr",
            description="ransomware encryption behaviour",
            technique_id="T1486",
            likelihood_ratio=20.0,
            severity="critical",
            timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
            raw={"entity_type": "server"},
        ))

        records = audit.all_records()
        assert records
        record = records[-1]

        for key in ("id", "timestamp", "actor", "action", "target"):
            assert key in record, f"audit record missing required field {key!r}"

        assert record.get("reasoning"), (
            "an audit record must explain WHY the decision was made, not just "
            "that it happened"
        )

    async def test_audit_trail_is_tamper_evident(self):
        from datetime import datetime, timezone

        from app.world_model import Observation, world_model
        from app.world_model.audit import audit

        for index in range(3):
            await world_model.ingest_observation(Observation(
                entity_id=f"srv-chain-{index}",
                source="edr",
                description=f"detection {index}",
                technique_id="T1003",
                likelihood_ratio=8.0,
                severity="high",
                timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
                raw={"entity_type": "server"},
            ))

        verification = audit.verify_chain()
        # The audit module reports integrity as `intact` plus a list of broken
        # link indices; accept `valid` too in case the field is renamed.
        intact = verification.get("intact", verification.get("valid"))
        assert intact is True, (
            f"audit hash chain failed verification: {verification}"
        )
        assert not verification.get("broken_at"), (
            f"audit chain has broken links at {verification.get('broken_at')}"
        )
        assert verification.get("records", 0) >= 3

    async def test_decision_execution_is_audited(self):
        """Executing a containment option must leave a record."""
        from app.world_model.audit import audit
        from app.world_model.decision_engine import decision_engine

        options = decision_engine.options().get("options", [])
        if not options:
            pytest.skip("decision engine produced no options for an empty world")

        before = len(audit.all_records())
        decision_engine.execute(options[0]["id"], approved_by="test-operator")
        after = audit.all_records()

        assert len(after) > before, (
            "executing a containment option produced no audit record"
        )


class TestRunnerReport:
    @pytest.mark.slow
    async def test_full_report_has_all_sections(self):
        from app.evaluation.runner import format_console_report, run_full_evaluation

        report = await run_full_evaluation(
            benign_count=400, scenario_repeats=1, max_timing_scenarios=1
        )

        for section in ("detection", "attribution", "response_coverage",
                        "mttd_mttr"):
            assert section in report, f"report missing section {section!r}"

        assert report["generated_at"]
        assert report["dataset_provenance"]["is_synthetic"] is True
        assert report["seed"] is not None
        assert len(report["criteria"]) == 5, (
            "the report must cover all five judged criteria"
        )
        assert "honesty_statement" in report

        text = format_console_report(report)
        assert "SENTINEL EVALUATION REPORT" in text
        assert "CAVEATS AND LIMITATIONS" in text

    @pytest.mark.slow
    async def test_report_is_cached(self):
        from app.evaluation.runner import get_last_report, run_full_evaluation

        report = await run_full_evaluation(
            benign_count=300, scenario_repeats=1, max_timing_scenarios=1
        )
        assert get_last_report() is report

    @pytest.mark.slow
    async def test_baseline_is_labelled_external(self):
        from app.evaluation.runner import run_full_evaluation

        report = await run_full_evaluation(
            benign_count=300, scenario_repeats=1, max_timing_scenarios=1
        )
        timing = report["mttd_mttr"]

        assert timing["baseline_is_external_reference"] is True
        assert timing["baseline_was_measured_here"] is False
        assert timing["baseline_source"], "the baseline figure must cite a source"
        assert "comparability_warning" in timing
        assert timing["reads_incident_seed_data"] is False, (
            "MTTR must not be read from the hardcoded mttr_minutes values in "
            "scripts/create_sample_incidents.py"
        )
