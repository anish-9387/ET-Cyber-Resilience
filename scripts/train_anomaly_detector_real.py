#!/usr/bin/env python3
"""Train and evaluate Sentinel's anomaly detector on a real public NIDS dataset.

Default dataset: UNSW-NB15 (training-set partition), a well-known network
intrusion benchmark, downloaded from a public Hugging Face mirror. BETH is
supported as a fallback but is Kaggle-auth-gated, so it must be supplied with
``--path`` rather than auto-downloaded.

Pipeline:
  1. Download / locate the CSV, and load it via
     ``app.evaluation.datasets.load_external_dataset`` for honest label and
     provenance handling. The pandas feature matrix is cross-checked against the
     loader's malicious count and the run aborts on any mismatch.
  2. Stratified train/test split (seed is fixed and recorded).
  3. Fit preprocessing (categorical vocab + StandardScaler) on train only.
  4. Train an unsupervised IsolationForest (features only, no labels) and a
     supervised RandomForest (features + labels) on the identical split.
  5. Register both in ModelRegistry with full metadata and persist them with the
     scaler and feature schema bundled in, then evaluate on the held-out split.

Run (from repo root, with the backend venv):
    backend/venv/bin/python scripts/train_anomaly_detector_real.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.evaluation.datasets import load_external_dataset  # noqa: E402
from app.evaluation.real_data_eval import evaluate_real_models  # noqa: E402
from app.ml.anomaly_detector import AnomalyDetector  # noqa: E402
from app.ml.model_registry import ModelRegistry  # noqa: E402
from app.ml.real_data_detector import DetectorArtifact, fit_feature_spec, transform  # noqa: E402

DATASETS: Dict[str, Dict] = {
    "unsw": {
        "key_prefix": "unsw_nb15",
        "filename": "UNSW_NB15_training-set.csv",
        "url": "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/UNSW_NB15_training-set.csv",
        "license": "UNSW-NB15, Moustafa & Slay 2015; free for research use (UNSW Canberra).",
        "label_column": "label",
        "drop_columns": ["id", "label", "attack_cat"],
        "categorical_columns": ["proto", "service", "state"],
        "caveat": (
            "UNSW-NB15 is synthetic lab traffic generated with the IXIA "
            "PerfectStorm tool, not a real production capture. It is a real, "
            "widely-cited public benchmark - but 'real benchmark', not "
            "'real-world deployment traffic'."
        ),
    },
    "beth": {
        "key_prefix": "beth",
        "filename": "labelled_data.csv",
        "url": None,
        "license": "BETH (Highnam et al. 2021), Kaggle katehighnam/beth-dataset.",
        "label_column": "evil",
        "drop_columns": ["evil", "sus", "timestamp"],
        "categorical_columns": ["processName", "hostName", "eventName"],
        "caveat": (
            "BETH is host/kernel behavioural telemetry (closer to this project's "
            "UEBA framing). It is Kaggle-auth-gated, so this script cannot "
            "auto-download it; supply the CSV with --path."
        ),
    },
}


def _download(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        print(f"[data] using cached {dest} ({dest.stat().st_size/1e6:.1f} MB)")
        return
    if not url:
        raise FileNotFoundError(
            f"No file at {dest} and no download URL for this dataset. "
            "Supply the CSV with --path."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[data] downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-train/1.0"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as out:
        total = 0
        while chunk := resp.read(1 << 20):
            out.write(chunk)
            total += len(chunk)
    tmp.rename(dest)
    print(f"[data] saved {dest} ({total/1e6:.1f} MB)")


def _round_floats(obj):
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(v) for v in obj]
    if isinstance(obj, float):
        return round(obj, 6)
    return obj


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", choices=list(DATASETS), default="unsw")
    parser.add_argument("--path", type=Path, help="Local CSV to use instead of downloading")
    parser.add_argument("--data-dir", type=Path, default=REPO_ROOT / "backend" / "data")
    parser.add_argument("--models-dir", type=Path, default=REPO_ROOT / "backend" / "models" / "real")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-rows", type=int, default=None, help="Cap rows (for a quick run)")
    parser.add_argument("--max-categories", type=int, default=50)
    args = parser.parse_args()

    cfg = DATASETS[args.dataset]
    csv_path = args.path or (args.data_dir / cfg["key_prefix"] / cfg["filename"])
    _download(cfg["url"], csv_path)
    download_date = date.fromtimestamp(csv_path.stat().st_mtime).isoformat()

    external = load_external_dataset(csv_path, label_column=cfg["label_column"], max_rows=args.max_rows)
    provenance = external.provenance
    print(f"[load] {provenance['dataset']}: {provenance['total_records']} rows, "
          f"{provenance['malicious_records']} malicious ({provenance['malicious_rate']:.3%})")

    df = pd.read_csv(csv_path, encoding="utf-8-sig", nrows=args.max_rows, low_memory=False)
    label_col = cfg["label_column"]
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not in CSV columns: {list(df.columns)[:20]}")
    y = (pd.to_numeric(df[label_col], errors="coerce").fillna(0).astype(int) > 0).astype(int).to_numpy()

    if int(y.sum()) != int(provenance["malicious_records"]):
        raise ValueError(
            "Label mismatch between pandas and load_external_dataset: "
            f"{int(y.sum())} vs {provenance['malicious_records']}. Refusing to train on "
            "inconsistent labels."
        )

    x_idx = np.arange(len(df))
    train_idx, test_idx = train_test_split(
        x_idx, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    train_df, test_df = df.iloc[train_idx].reset_index(drop=True), df.iloc[test_idx].reset_index(drop=True)
    y_train, y_test = y[train_idx], y[test_idx]

    spec, scaler, x_train = fit_feature_spec(
        train_df, cfg["drop_columns"], cfg["categorical_columns"], max_categories=args.max_categories
    )
    x_test = transform(test_df, spec, scaler)
    print(f"[features] {len(spec.feature_columns)} features "
          f"({len(spec.categorical_columns)} categorical, capped at {args.max_categories})")

    print("[train] IsolationForest (unsupervised, features only)")
    iso = AnomalyDetector(model_path=str(args.models_dir))
    iso.fit(x_train)

    print("[train] RandomForest (supervised)")
    rf = RandomForestClassifier(
        n_estimators=200, n_jobs=-1, random_state=args.seed, class_weight="balanced"
    )
    rf.fit(x_train, y_train)

    now = datetime.now(timezone.utc).isoformat()
    shared_meta = {
        "dataset": provenance["dataset"],
        "dataset_family": args.dataset,
        "source_url": cfg["url"],
        "license": cfg["license"],
        "download_date": download_date,
        "trained_at": now,
        "seed": args.seed,
        "split": {
            "train_size": int(len(train_idx)),
            "test_size": int(len(test_idx)),
            "test_fraction": args.test_size,
            "stratified": True,
        },
        "class_balance": {
            "train_malicious_rate": round(float(y_train.mean()), 6),
            "test_malicious_rate": round(float(y_test.mean()), 6),
        },
        "feature_schema": spec.to_metadata(),
        "caveat": cfg["caveat"],
    }

    iso_artifact = DetectorArtifact(
        kind="isolation_forest", model=iso, scaler=scaler, spec=spec,
        metadata={**shared_meta, "model": "IsolationForest",
                  "supervised": False, "params": iso.isolation_forest.get_params()},
    )
    rf_artifact = DetectorArtifact(
        kind="random_forest", model=rf, scaler=scaler, spec=spec,
        metadata={**shared_meta, "model": "RandomForestClassifier",
                  "supervised": True, "params": rf.get_params()},
    )

    registry = ModelRegistry(base_path=str(args.models_dir))
    iso_name = f"{cfg['key_prefix']}_isolation_forest"
    rf_name = f"{cfg['key_prefix']}_random_forest"
    registry.register(iso_name, iso_artifact, metadata=iso_artifact.metadata)
    registry.register(rf_name, rf_artifact, metadata=rf_artifact.metadata)
    registry.save(iso_name)
    registry.save(rf_name)
    print(f"[registry] saved {iso_name} and {rf_name} to {args.models_dir}")

    report = evaluate_real_models(
        {iso_name: iso_artifact, rf_name: rf_artifact}, test_df, y_test
    )
    report["dataset_provenance"] = {**provenance, "download_date": download_date, "caveat": cfg["caveat"]}
    report["generated_at"] = now

    report_path = args.models_dir / f"{cfg['key_prefix']}_eval_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w") as f:
        json.dump(_round_floats(report), f, indent=2, default=str)

    print("\n" + "=" * 74)
    print(f"  REAL-DATA EVALUATION - {provenance['dataset']}")
    print("=" * 74)
    for name, res in report["models"].items():
        print(f"\n  {name}  ({res['kind']})")
        print(f"    ROC-AUC          : {res['roc_auc']:.4f}")
        print(f"    Avg precision    : {res['average_precision']:.4f}")
        for pt in res["detection_rate_at_fixed_fpr"]:
            print(f"    det@FPR<={pt['target_fpr']:.0%}: {pt['detection_rate']:.4f} "
                  f"(achieved FPR {pt['achieved_fpr']:.4f})")
        cal = res["calibration"]
        if cal.get("applies"):
            print(f"    calibration slope: {cal['logistic_slope']:.3f} "
                  f"(positive={cal['slope_positive']}), Brier {cal['brier_score_minmax']:.4f}")
    print(f"\n  Report written to {report_path}")
    print(f"  Dataset caveat: {cfg['caveat']}")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
