"""Artifacts for models trained on real public NIDS datasets (UNSW-NB15, BETH).

The bundle carries the fitted model together with the exact preprocessing it was
trained under - the fitted ``StandardScaler``, the categorical vocabulary, and
the ordered feature-column list. Inference reindexes incoming data to that same
schema, so a model can never be served against features it was not trained on.
There is no silent fallback: a missing scaler, empty schema, or unfitted model
raises rather than returning a degraded score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

OTHER_TOKEN = "<OTHER>"


@dataclass
class FeatureSpec:
    """Preprocessing schema shared by every model trained on one split."""

    drop_columns: List[str]
    categorical_columns: List[str]
    categorical_vocab: Dict[str, List[str]]
    feature_columns: List[str]

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "n_features": len(self.feature_columns),
            "drop_columns": list(self.drop_columns),
            "categorical_columns": list(self.categorical_columns),
            "categorical_cardinality": {
                col: len(vocab) for col, vocab in self.categorical_vocab.items()
            },
            "feature_columns": list(self.feature_columns),
        }


def _cap_categoricals(
    df: pd.DataFrame,
    categorical_columns: Sequence[str],
    vocab: Dict[str, List[str]],
) -> pd.DataFrame:
    out = df.copy()
    for col in categorical_columns:
        if col not in out.columns:
            out[col] = OTHER_TOKEN
            continue
        allowed = set(vocab[col])
        out[col] = out[col].astype(str).where(out[col].astype(str).isin(allowed), OTHER_TOKEN)
    return out


def fit_feature_spec(
    train_df: pd.DataFrame,
    drop_columns: Sequence[str],
    categorical_columns: Sequence[str],
    max_categories: int = 50,
) -> Tuple[FeatureSpec, StandardScaler, np.ndarray]:
    """Fit the preprocessing on the training split only.

    Returns the schema, the fitted scaler, and the scaled training matrix.
    Categorical columns are capped to their most frequent ``max_categories``
    values (the rest collapse to ``<OTHER>``) so the one-hot schema is bounded
    and reproducible; the chosen vocabulary is persisted for inference.
    """
    drop_columns = [c for c in drop_columns if c in train_df.columns]
    categorical_columns = [c for c in categorical_columns if c in train_df.columns]

    vocab: Dict[str, List[str]] = {}
    for col in categorical_columns:
        top = (
            train_df[col].astype(str).value_counts().head(max_categories).index.tolist()
        )
        vocab[col] = sorted(top) + [OTHER_TOKEN]

    capped = _cap_categoricals(train_df.drop(columns=drop_columns), categorical_columns, vocab)
    dummies = pd.get_dummies(capped, columns=categorical_columns, dummy_na=False)
    dummies = dummies.apply(pd.to_numeric, errors="coerce").fillna(0.0)

    feature_columns = list(dummies.columns)
    if not feature_columns:
        raise ValueError("fit_feature_spec produced an empty feature schema")

    scaler = StandardScaler()
    x_train = scaler.fit_transform(dummies.to_numpy(dtype=float))

    spec = FeatureSpec(
        drop_columns=list(drop_columns),
        categorical_columns=list(categorical_columns),
        categorical_vocab=vocab,
        feature_columns=feature_columns,
    )
    return spec, scaler, x_train


def transform(raw_df: pd.DataFrame, spec: FeatureSpec, scaler: StandardScaler) -> np.ndarray:
    """Apply the training-time preprocessing to new rows.

    Fails loudly if the schema is empty - a model must never score against a
    silently-different feature space than it was trained on.
    """
    if not spec.feature_columns:
        raise ValueError("FeatureSpec has no feature_columns; refusing to transform")
    if scaler is None:
        raise ValueError("No scaler supplied; refusing to transform without training-time scaling")

    present_drop = [c for c in spec.drop_columns if c in raw_df.columns]
    capped = _cap_categoricals(
        raw_df.drop(columns=present_drop), spec.categorical_columns, spec.categorical_vocab
    )
    dummies = pd.get_dummies(capped, columns=spec.categorical_columns, dummy_na=False)
    dummies = dummies.apply(pd.to_numeric, errors="coerce").fillna(0.0)
    aligned = dummies.reindex(columns=spec.feature_columns, fill_value=0.0)
    return scaler.transform(aligned.to_numpy(dtype=float))


@dataclass
class DetectorArtifact:
    """A trained model plus the preprocessing needed to serve it.

    ``kind`` is ``isolation_forest`` (unsupervised) or ``random_forest``
    (supervised). ``score`` returns a malicious-likelihood score where higher
    means more likely an attack, for both kinds, so downstream ROC/threshold
    code is model-agnostic.
    """

    kind: str
    model: Any
    scaler: StandardScaler
    spec: FeatureSpec
    metadata: Dict[str, Any] = field(default_factory=dict)

    def _validate(self) -> None:
        if self.scaler is None:
            raise ValueError(f"Artifact '{self.kind}' has no scaler; cannot score")
        if self.spec is None or not self.spec.feature_columns:
            raise ValueError(f"Artifact '{self.kind}' has no feature schema; cannot score")
        if self.model is None:
            raise ValueError(f"Artifact '{self.kind}' has no model; cannot score")

    def score(self, raw_df: pd.DataFrame) -> np.ndarray:
        self._validate()
        x = transform(raw_df, self.spec, self.scaler)
        if self.kind == "isolation_forest":
            detector = self.model
            forest = getattr(detector, "isolation_forest", None)
            if forest is None or not getattr(detector, "is_fitted", False):
                raise ValueError("IsolationForest artifact is not fitted")
            return -forest.score_samples(x)
        if self.kind == "random_forest":
            proba = getattr(self.model, "predict_proba", None)
            if proba is None:
                raise ValueError("random_forest artifact has no predict_proba")
            return proba(x)[:, 1]
        raise ValueError(f"Unknown artifact kind: {self.kind}")
