"""
PhishShield – Model Training Script.

Loads the preprocessed email dataset, builds an sklearn Pipeline with a
VotingClassifier (Logistic Regression + Random Forest), evaluates it on a
held-out test set, and persists the pipeline and metrics to disk.

Run after download_data.py has created backend/ml/data/emails.csv.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from backend.ml.features import build_full_pipeline

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
DATA_CSV = _HERE / "data" / "emails.csv"
PIPELINE_PKL = _HERE / "pipeline.pkl"
MODEL_PKL = _HERE / "model.pkl"
METRICS_JSON = _HERE / "metrics.json"

# ---------------------------------------------------------------------------
# Hyper-parameters
# ---------------------------------------------------------------------------
TEST_SIZE = 0.20
RANDOM_STATE = 42
LR_MAX_ITER = 1000
RF_N_ESTIMATORS = 200
RF_MAX_DEPTH = 20


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_dataset(csv_path: Path = DATA_CSV) -> tuple[list[dict[str, Any]], list[int]]:
    """
    Load the email CSV and return samples as dicts plus integer labels.

    Parameters
    ----------
    csv_path:
        Path to the CSV produced by ``download_data.py``.

    Returns
    -------
    tuple[list[dict[str, Any]], list[int]]
        * ``X`` – list of ``{'text': str}`` dicts (one per email)
        * ``y`` – list of integer labels (0 = legitimate, 1 = phishing)

    Raises
    ------
    FileNotFoundError
        If the CSV does not exist.
    """
    if not csv_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {csv_path}. "
            "Please run backend/ml/download_data.py first."
        )

    print(f"[DATA] Loading dataset from {csv_path} …")
    df = pd.read_csv(csv_path)
    required = {"text", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing required columns: {missing}")

    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    source_dist = df["source"].value_counts().to_dict() if "source" in df.columns else {}
    label_dist = df["label"].value_counts().to_dict()
    print(f"[DATA] Rows loaded       : {len(df)}")
    print(f"[DATA] Label distribution: {label_dist}")
    if source_dist:
        print(f"[DATA] Source breakdown  : {source_dist}")

    X = [{"text": row["text"]} for _, row in df.iterrows()]
    y = df["label"].tolist()
    return X, y


# ---------------------------------------------------------------------------
# Model construction
# ---------------------------------------------------------------------------

def build_voting_classifier() -> VotingClassifier:
    """
    Build a soft-voting ensemble of Logistic Regression and Random Forest.

    Returns
    -------
    VotingClassifier
        Unfitted ensemble.
    """
    lr = LogisticRegression(
        max_iter=LR_MAX_ITER,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        solver="lbfgs",
        C=1.0,
    )
    rf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
    )
    return VotingClassifier(
        estimators=[("lr", lr), ("rf", rf)],
        voting="soft",
        weights=[1, 1],
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(
    pipeline: Any,
    X_test: list[dict[str, Any]],
    y_test: list[int],
) -> dict[str, Any]:
    """
    Evaluate the fitted pipeline on the held-out test set.

    Parameters
    ----------
    pipeline:
        Fitted sklearn Pipeline.
    X_test:
        List of sample dicts.
    y_test:
        True integer labels.

    Returns
    -------
    dict[str, Any]
        Metrics: accuracy, precision, recall, f1, roc_auc, confusion_matrix.
    """
    y_pred: np.ndarray = pipeline.predict(X_test)
    y_prob: np.ndarray = pipeline.predict_proba(X_test)[:, 1]

    metrics: dict[str, Any] = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 6),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 6),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "test_size": len(y_test),
        "positive_rate": round(float(np.mean(y_test)), 6),
    }
    return metrics


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_training_report(metrics: dict[str, Any], elapsed: float) -> None:
    """
    Print a human-readable training report to stdout.

    Parameters
    ----------
    metrics:
        Dict returned by :func:`evaluate`.
    elapsed:
        Training wall-clock time in seconds.
    """
    cm = metrics["confusion_matrix"]
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    bar = "=" * 60
    print(f"\n{bar}")
    print("PhishShield  –  Training Report")
    print(bar)
    print(f"  Test samples : {metrics['test_size']}")
    print(f"  Training time: {elapsed:.1f}s")
    print(f"\n  Accuracy     : {metrics['accuracy']:.4f}")
    print(f"  Precision    : {metrics['precision']:.4f}")
    print(f"  Recall       : {metrics['recall']:.4f}")
    print(f"  F1 Score     : {metrics['f1']:.4f}")
    print(f"  ROC-AUC      : {metrics['roc_auc']:.4f}")
    print("\n  Confusion Matrix (rows=actual, cols=predicted):")
    print("               Predicted-Legit  Predicted-Phish")
    print(f"  Actual-Legit      {tn:>7}          {fp:>7}")
    print(f"  Actual-Phish      {fn:>7}          {tp:>7}")
    print(bar)


# ---------------------------------------------------------------------------
# Main training entry-point
# ---------------------------------------------------------------------------

def train(csv_path: Path = DATA_CSV) -> None:
    """
    End-to-end training function.

    1. Load dataset from *csv_path*.
    2. Split 80 / 20 with stratification.
    3. Build and fit the Pipeline (FeatureUnion + VotingClassifier).
    4. Evaluate on the held-out test set.
    5. Persist ``pipeline.pkl``, ``model.pkl``, and ``metrics.json``.
    6. Print a training report.

    Parameters
    ----------
    csv_path:
        Path to the email CSV file (default: ``backend/ml/data/emails.csv``).
    """
    X, y = load_dataset(csv_path)

    print(f"\n[SPLIT] Splitting {len(X)} samples: 80% train / 20% test (stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    print(f"[SPLIT] Train: {len(X_train)}  |  Test: {len(X_test)}")

    print("\n[MODEL] Building pipeline …")
    clf = build_voting_classifier()
    pipeline = build_full_pipeline(clf)

    print("[MODEL] Fitting pipeline (this may take a few minutes) …")
    t0 = time.perf_counter()
    pipeline.fit(X_train, y_train)
    elapsed = time.perf_counter() - t0
    print(f"[MODEL] Training complete in {elapsed:.1f}s.")

    print("\n[EVAL] Evaluating on held-out test set …")
    metrics = evaluate(pipeline, X_test, y_test)

    # ---- Persist ----
    print(f"\n[SAVE] Writing pipeline → {PIPELINE_PKL}")
    joblib.dump(pipeline, PIPELINE_PKL, compress=3)

    # Also save just the classifier for external use
    print(f"[SAVE] Writing model     → {MODEL_PKL}")
    joblib.dump(pipeline.named_steps["clf"], MODEL_PKL, compress=3)

    metrics["pipeline_path"] = str(PIPELINE_PKL)
    metrics["model_path"] = str(MODEL_PKL)
    metrics["training_seconds"] = round(elapsed, 2)

    print(f"[SAVE] Writing metrics   → {METRICS_JSON}")
    METRICS_JSON.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print_training_report(metrics, elapsed)
    print(f"\n[DONE] Artifacts written to {_HERE}")


if __name__ == "__main__":
    train()
