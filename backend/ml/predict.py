"""
PhishShield – Prediction Module.

Provides:
  - load_pipeline  : load the trained sklearn Pipeline (LRU-cached)
  - predict        : classify an email and return probability, label,
                     confidence, and the top contributing features
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
from scipy.sparse import issparse

# ---------------------------------------------------------------------------
# Paths (resolved relative to this file)
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
PIPELINE_PKL = _HERE / "pipeline.pkl"

# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------

@dataclass
class EmailFeatureInput:
    """
    Input to the :func:`predict` function.

    Attributes
    ----------
    text:
        Full email body (plain-text or HTML).
    url_features_dict:
        Pre-extracted URL features produced by
        :func:`~backend.ml.features.extract_url_features`.
        Pass an empty dict to let the pipeline compute them from *text*.
    header_features_dict:
        Pre-extracted header features produced by
        :func:`~backend.ml.features.extract_header_features`.
        Pass an empty dict when headers are unavailable.
    subject:
        Email subject line (may be empty).
    """
    text: str
    url_features_dict: dict[str, float] = field(default_factory=dict)
    header_features_dict: dict[str, str] = field(default_factory=dict)
    subject: str = ""


@dataclass
class PredictionResult:
    """
    Output of the :func:`predict` function.

    Attributes
    ----------
    probability:
        Probability that the email is phishing (0.0 – 1.0).
    label:
        Human-readable classification: ``'phishing'`` or ``'legitimate'``.
    confidence:
        Model confidence in its prediction (max(p, 1-p)).
    top_features:
        Up to 10 most impactful features driving a *phishing* classification.
        Each entry is ``{'name': str, 'weight': float}``.
    note:
        Optional diagnostic note (e.g. ``'model not trained'``).
    """
    probability: float
    label: str
    confidence: float
    top_features: list[dict[str, float]]
    note: str = ""


# ---------------------------------------------------------------------------
# Pipeline loader (cached)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def load_pipeline() -> Any | None:
    """
    Load the trained sklearn Pipeline from disk.

    The result is cached after the first call (via :func:`functools.lru_cache`)
    so subsequent predictions do not incur disk I/O.

    Returns
    -------
    Any | None
        The fitted Pipeline, or ``None`` if ``pipeline.pkl`` does not exist.
    """
    if not PIPELINE_PKL.exists():
        warnings.warn(
            f"PhishShield: pipeline.pkl not found at {PIPELINE_PKL}. "
            "Run backend/ml/train.py to train the model.",
            RuntimeWarning,
            stacklevel=2,
        )
        return None

    import joblib  # local import to keep module importable without joblib if unused
    pipeline = joblib.load(PIPELINE_PKL)
    return pipeline


# ---------------------------------------------------------------------------
# Feature name helpers
# ---------------------------------------------------------------------------

def _get_feature_names(pipeline: Any) -> list[str]:
    """
    Extract ordered feature names from the fitted FeatureUnion inside *pipeline*.

    Returns
    -------
    list[str]
        List of feature name strings; falls back to positional names if
        introspection fails.
    """
    try:
        from backend.ml.features import EngineeredFeatureTransformer

        feature_union = pipeline.named_steps["features"]
        names: list[str] = []

        for transformer_name, transformer in feature_union.transformer_list:
            if transformer_name == "tfidf_text":
                # TF-IDF names are on the inner vectoriser
                tfidf = transformer.named_steps["tfidf"]
                names.extend(tfidf.get_feature_names_out().tolist())
            elif transformer_name == "engineered":
                names.extend(EngineeredFeatureTransformer.FEATURE_NAMES)

        return names
    except Exception:  # noqa: BLE001
        return []


def _get_top_features(
    pipeline: Any,
    sample: dict[str, Any],
    n_top: int = 10,
) -> list[dict[str, float]]:
    """
    Identify the top *n_top* features driving a phishing prediction.

    Strategy
    --------
    1. Transform the single sample through the FeatureUnion to get the feature
       vector.
    2. Extract per-class feature importances from each sub-estimator:
       - LogisticRegression: use ``coef_[1]`` (phishing class coefficients)
       - RandomForestClassifier: use ``feature_importances_``
    3. Element-wise multiply importances by the feature vector values.
    4. Return the top *n_top* by absolute signed contribution.

    Parameters
    ----------
    pipeline:
        Fitted Pipeline.
    sample:
        Single email dict (same format as training).
    n_top:
        Number of top features to return.

    Returns
    -------
    list[dict[str, float]]
        Sorted list of ``{'name': str, 'weight': float}`` dicts.
    """
    try:
        feature_union = pipeline.named_steps["features"]
        X_vec = feature_union.transform([sample])
        if issparse(X_vec):
            X_arr = np.asarray(X_vec.todense()).flatten()
        else:
            X_arr = np.array(X_vec).flatten()

        clf = pipeline.named_steps["clf"]
        combined_importance = np.zeros(len(X_arr))

        for name, estimator in clf.estimators_:
            if hasattr(estimator, "coef_"):
                # LR: coefficients for phishing class (index 1)
                coef = np.array(estimator.coef_).flatten()
                if len(coef) == len(X_arr):
                    combined_importance += coef * X_arr
            elif hasattr(estimator, "feature_importances_"):
                fi = np.array(estimator.feature_importances_).flatten()
                if len(fi) == len(X_arr):
                    # Weight by phishing direction (positive = phishing)
                    combined_importance += fi * np.sign(X_arr)

        feature_names = _get_feature_names(pipeline)
        # Pad or trim names to match vector length
        while len(feature_names) < len(X_arr):
            feature_names.append(f"feature_{len(feature_names)}")
        feature_names = feature_names[: len(X_arr)]

        # Sort by contribution (descending) — most phishing-indicative first
        indices = np.argsort(combined_importance)[::-1][:n_top]
        top: list[dict[str, float]] = []
        for idx in indices:
            weight = float(combined_importance[idx])
            if weight <= 0.0:
                continue  # skip features with no positive (phishing) contribution
            top.append({"name": str(feature_names[idx]), "weight": round(weight, 6)})

        return top[:n_top]
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict(email: EmailFeatureInput) -> PredictionResult:
    """
    Classify a single email as phishing or legitimate.

    Parameters
    ----------
    email:
        :class:`EmailFeatureInput` describing the email to classify.

    Returns
    -------
    PredictionResult
        Contains ``probability``, ``label``, ``confidence``,
        ``top_features``, and an optional ``note``.

    Notes
    -----
    * If ``pipeline.pkl`` has not been created yet, the function returns a
      safe fallback result with ``probability=0.1``, ``label='legitimate'``,
      ``confidence=0.1``, and ``note='model not trained'`` — **no exception
      is raised**.
    * Header features supplied via ``email.header_features_dict`` are passed
      through to the pipeline as the ``'headers'`` key; the pipeline's
      :class:`~backend.ml.features.EngineeredFeatureTransformer` reads them
      transparently.
    """
    pipeline = load_pipeline()

    # ---- Graceful fallback when model is absent ----
    if pipeline is None:
        return PredictionResult(
            probability=0.1,
            label="legitimate",
            confidence=0.1,
            top_features=[],
            note="model not trained",
        )

    # Build the sample dict
    sample: dict[str, Any] = {
        "text": email.text,
        "subject": email.subject,
        "headers": email.header_features_dict,
    }

    try:
        proba: np.ndarray = pipeline.predict_proba([sample])[0]
        phishing_prob = float(proba[1])
        label = "phishing" if phishing_prob >= 0.5 else "legitimate"
        confidence = float(max(proba))
        top_features = _get_top_features(pipeline, sample, n_top=10)

        return PredictionResult(
            probability=round(phishing_prob, 6),
            label=label,
            confidence=round(confidence, 6),
            top_features=top_features,
        )

    except Exception as exc:  # noqa: BLE001
        warnings.warn(
            f"PhishShield prediction error: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )
        return PredictionResult(
            probability=0.5,
            label="legitimate",
            confidence=0.5,
            top_features=[],
            note=f"prediction_error: {exc}",
        )


# ---------------------------------------------------------------------------
# Convenience: batch prediction
# ---------------------------------------------------------------------------

def predict_batch(emails: list[EmailFeatureInput]) -> list[PredictionResult]:
    """
    Classify a list of emails in sequence.

    Parameters
    ----------
    emails:
        List of :class:`EmailFeatureInput` objects.

    Returns
    -------
    list[PredictionResult]
        One result per input email, in order.
    """
    return [predict(e) for e in emails]


def predict_phishing(
    text: str,
    subject: str = "",
    url_features: dict | None = None,
    header_features: dict | None = None,
) -> PredictionResult:
    """
    Convenience wrapper matching the pipeline interface.
    """
    inp = EmailFeatureInput(
        text=text,
        subject=subject,
        url_features_dict=url_features or {},
        header_features_dict=header_features or {},
    )
    return predict(inp)

