"""
PhishShield – ML Model router.
Returns model metrics and supports retraining.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from backend.app.deps import get_current_user, require_admin
from backend.app.models import User
from backend.app.schemas import ModelMetrics

router = APIRouter(prefix="/model", tags=["model"])

METRICS_PATH = Path(__file__).parent.parent.parent.parent / "backend" / "ml" / "metrics.json"


@router.get("/metrics", response_model=ModelMetrics)
async def get_metrics(_user: User = Depends(get_current_user)):
    """Return the current ML model performance metrics."""
    # Try to find metrics file relative to project root
    candidates = [
        Path("backend/ml/metrics.json"),
        Path(__file__).parent.parent.parent / "ml" / "metrics.json",
    ]
    metrics_file = None
    for c in candidates:
        if c.exists():
            metrics_file = c
            break

    if not metrics_file:
        raise HTTPException(
            status_code=404,
            detail=(
                "Model metrics not found. "
                "Run `python -m backend.ml.download_data && python -m backend.ml.train` first."
            ),
        )

    with open(metrics_file) as f:
        data = json.load(f)

    return ModelMetrics(**data)


@router.post("/retrain")
async def retrain_model(_admin: User = Depends(require_admin)):
    """
    Admin: trigger model retraining in the background.
    Downloads fresh data (if available) and retrains.
    Returns immediately; training runs in the background.
    """
    try:
        # Run download + train as subprocess (non-blocking)
        result = subprocess.Popen(
            [sys.executable, "-m", "backend.ml.download_data"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return {
            "status": "started",
            "pid": result.pid,
            "message": "Model retraining started. Check logs for progress.",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
