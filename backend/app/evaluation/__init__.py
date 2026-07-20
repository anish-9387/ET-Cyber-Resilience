"""Sentinel evaluation harness.

This package computes *real, reproducible* numbers for the five criteria the
project is judged on:

1. Anomaly detection rate / false positive rate  -> ``detection_eval``
2. APT attribution accuracy at ATT&CK technique level -> ``attribution_eval``
3. Incident response automation coverage -> ``response_eval``
4. MTTD / MTTR vs a documented baseline -> ``timing_eval``
5. Auditability of automated actions -> asserted in ``backend/tests``

Design rule for this package: **never fabricate, floor, clamp or round a metric
toward something flattering.** Where a capability does not exist (e.g. real
firewall integrations), the payload says so explicitly rather than omitting it.
The synthetic corpus is labelled as synthetic everywhere it is reported.
"""

from app.evaluation.datasets import (
    LabeledRecord,
    BenchmarkDataset,
    generate_benchmark_dataset,
    load_external_dataset,
    DEFAULT_SEED,
)

__all__ = [
    "LabeledRecord",
    "BenchmarkDataset",
    "generate_benchmark_dataset",
    "load_external_dataset",
    "DEFAULT_SEED",
]
