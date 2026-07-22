"""Tests for the real-dataset detector artifact: persistence, shape, fail-loud.

These do not download anything. They build a tiny synthetic frame, exercise the
same preprocessing/save/load path the training script uses, and assert that a
missing scaler, empty schema, or missing registry entry raises rather than
silently degrading.
"""

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from app.ml.anomaly_detector import AnomalyDetector
from app.ml.model_registry import ModelRegistry
from app.ml.real_data_detector import (
    DetectorArtifact,
    FeatureSpec,
    fit_feature_spec,
    transform,
)


def _toy_frame(n: int = 120) -> tuple[pd.DataFrame, np.ndarray]:
    rng = np.random.default_rng(0)
    proto = rng.choice(["tcp", "udp", "icmp"], size=n)
    y = (rng.random(n) < 0.4).astype(int)
    df = pd.DataFrame(
        {
            "id": np.arange(n),
            "dur": rng.random(n) + y * 3.0,
            "sbytes": rng.integers(0, 5000, n) + y * 2000,
            "proto": proto,
            "label": y,
        }
    )
    return df, y


def _build_artifacts(tmp_path):
    df, y = _toy_frame()
    spec, scaler, x = fit_feature_spec(df, ["id", "label"], ["proto"], max_categories=10)

    iso = AnomalyDetector(model_path=str(tmp_path))
    iso.fit(x)
    rf = RandomForestClassifier(n_estimators=20, random_state=0).fit(x, y)

    iso_art = DetectorArtifact("isolation_forest", iso, scaler, spec, {"dataset": "toy"})
    rf_art = DetectorArtifact("random_forest", rf, scaler, spec, {"dataset": "toy"})
    return df, y, iso_art, rf_art


def test_save_load_and_score_shape(tmp_path):
    df, y, iso_art, rf_art = _build_artifacts(tmp_path)
    registry = ModelRegistry(base_path=str(tmp_path))

    registry.register("toy_iso", iso_art, metadata=iso_art.metadata)
    registry.register("toy_rf", rf_art, metadata=rf_art.metadata)
    registry.save("toy_iso")
    registry.save("toy_rf")

    fresh = ModelRegistry(base_path=str(tmp_path))
    loaded_iso = fresh.load("toy_iso")
    loaded_rf = fresh.load("toy_rf")

    assert isinstance(loaded_iso, DetectorArtifact)
    assert loaded_iso.scaler is not None
    assert loaded_iso.spec.feature_columns == iso_art.spec.feature_columns

    sample = df.iloc[:5]
    iso_scores = loaded_iso.score(sample)
    rf_scores = loaded_rf.score(sample)
    assert iso_scores.shape == (5,)
    assert rf_scores.shape == (5,)
    assert np.all((rf_scores >= 0) & (rf_scores <= 1))

    meta = fresh.get_metadata("toy_rf")
    assert meta["metadata"]["dataset"] == "toy"


def test_transform_reindexes_unseen_categories(tmp_path):
    df, _, iso_art, _ = _build_artifacts(tmp_path)
    novel = df.iloc[:3].copy()
    novel["proto"] = "quic"
    out = transform(novel, iso_art.spec, iso_art.scaler)
    assert out.shape[0] == 3
    assert out.shape[1] == len(iso_art.spec.feature_columns)


def test_missing_scaler_fails_loudly(tmp_path):
    _, _, iso_art, _ = _build_artifacts(tmp_path)
    broken = DetectorArtifact("isolation_forest", iso_art.model, None, iso_art.spec, {})
    with pytest.raises(ValueError):
        broken.score(_toy_frame()[0].iloc[:2])


def test_empty_feature_schema_fails_loudly(tmp_path):
    _, _, iso_art, _ = _build_artifacts(tmp_path)
    empty_spec = FeatureSpec([], [], {}, [])
    broken = DetectorArtifact("isolation_forest", iso_art.model, iso_art.scaler, empty_spec, {})
    with pytest.raises(ValueError):
        broken.score(_toy_frame()[0].iloc[:2])


def test_missing_registry_entry_fails_loudly(tmp_path):
    registry = ModelRegistry(base_path=str(tmp_path))
    with pytest.raises(FileNotFoundError):
        registry.load("does_not_exist")


def test_flow_model_and_live_detector_are_different_feature_spaces(tmp_path):
    from app.agents.behaviour_agent import BehaviourProfile

    live_dim = len(BehaviourProfile("e1", "user").to_vector())
    df, _, iso_art, _ = _build_artifacts(tmp_path)
    flow_dim = len(iso_art.spec.feature_columns)

    # Different feature spaces: the flow model cannot be dropped onto the live
    # behavioural vector. (Real UNSW schema is 110 features vs the live 10; the
    # toy frame here is smaller, so assert difference, not magnitude.)
    assert live_dim != flow_dim
    assert iso_art.spec.categorical_columns == ["proto"]


def test_live_serving_path_does_not_reference_flow_model():
    """The UNSW/flow artifact must stay off the live path.

    This is the enforcement for the deliberate separation: the behavioural
    agent, the ingestion API and the services must not load the real-data model
    or its registry directory. If a future change wires them together, this
    test fails.
    """
    from pathlib import Path

    backend = Path(__file__).resolve().parents[1]
    forbidden = ("real_data_detector", "models/real", "unsw_nb15", "random_forest")
    offenders = []
    for area in ("app/agents", "app/api", "app/services"):
        for py in (backend / area).rglob("*.py"):
            text = py.read_text()
            for token in forbidden:
                if token in text:
                    offenders.append(f"{py.relative_to(backend)}: {token}")
    assert not offenders, f"live path references the offline flow model: {offenders}"
