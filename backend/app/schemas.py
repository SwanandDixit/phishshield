"""
PhishShield – Pydantic schemas for request/response validation.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


# ─── Auth ────────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Email Analysis ───────────────────────────────────────────────────────────


class EmailAnalysisRequest(BaseModel):
    """Raw RFC 2822 email bytes (base64-encoded) for analysis."""
    raw_email_b64: str
    source_ip: Optional[str] = None
    tls_info: Optional[dict[str, Any]] = None


class URLAnalysisRequest(BaseModel):
    url: str = Field(max_length=2048)


class RiskBreakdown(BaseModel):
    auth_score: float
    url_score: float
    attachment_score: float
    ml_score: float
    header_score: float
    crypto_score: float
    total: float
    hard_override: bool = False
    override_reason: Optional[str] = None


class EmailSummary(BaseModel):
    id: int
    message_id: Optional[str]
    received_at: datetime
    sender_address: Optional[str]
    subject: Optional[str]
    verdict: Optional[str]
    risk_score: Optional[float]
    tls_established: bool
    is_simulation: bool

    model_config = {"from_attributes": True}


class EmailDetail(BaseModel):
    id: int
    message_id: Optional[str]
    received_at: datetime
    sender_address: Optional[str]
    sender_display_name: Optional[str]
    reply_to: Optional[str]
    subject: Optional[str]
    recipients: Optional[list[str]]
    tls_protocol: Optional[str]
    tls_cipher: Optional[str]
    tls_established: bool
    spf_result: Optional[str]
    dkim_result: Optional[str]
    dmarc_result: Optional[str]
    auth_details: Optional[dict]
    sha256_hash: Optional[str]
    signature_valid: Optional[bool]
    hmac_valid: Optional[bool]
    replay_detected: bool
    crypto_details: Optional[dict]
    url_findings: Optional[dict]
    attachment_findings: Optional[dict]
    header_findings: Optional[dict]
    spoofing_findings: Optional[dict]
    ml_phishing_probability: Optional[float]
    ml_verdict: Optional[str]
    ml_top_features: Optional[list]
    risk_score: Optional[float]
    risk_breakdown: Optional[dict]
    verdict: Optional[str]
    delivered: bool
    quarantined: bool
    warning_message: Optional[str]
    sanitized_html: Optional[str]
    pipeline_timing: Optional[dict]
    explanation: Optional[dict]
    is_simulation: bool
    simulation_scenario: Optional[str]

    model_config = {"from_attributes": True}


# ─── Keys ────────────────────────────────────────────────────────────────────


class KeyCreateRequest(BaseModel):
    label: str = Field(max_length=255)
    domain: str = Field(max_length=255)
    key_type: str = Field(pattern="^(ED25519|RSA_PSS|HMAC)$")


class KeyOut(BaseModel):
    id: int
    label: str
    domain: str
    key_type: str
    public_key_pem: str
    is_active: bool
    created_at: datetime
    revoked_at: Optional[datetime]

    model_config = {"from_attributes": True}


class KeyGenerateResponse(BaseModel):
    """Returned once on key creation – private key shown only this once."""
    key: KeyOut
    private_key_pem: Optional[str] = None  # None for HMAC keys
    hmac_secret_b64: Optional[str] = None  # for HMAC keys


# ─── Dashboard ───────────────────────────────────────────────────────────────


class DashboardStats(BaseModel):
    total_emails: int
    legitimate: int
    suspicious: int
    malicious: int
    simulations: int
    avg_risk_score: float
    detections_today: int
    top_attack_types: list[dict]
    layer_catch_rates: dict[str, float]
    recent_verdicts: list[dict]


# ─── Simulation ──────────────────────────────────────────────────────────────


class SimulationRequest(BaseModel):
    scenario: str = Field(pattern="^(phishing|spoofing|tampering|replay|mitm|batch)$")
    iterations: int = Field(default=1, ge=1, le=50)
    include_benign: bool = True


class SimulationResult(BaseModel):
    scenario: str
    iterations: int
    results: list[dict]
    detection_rate: float
    false_positive_rate: Optional[float]
    avg_latency_ms: float
    summary: dict


# ─── Log ─────────────────────────────────────────────────────────────────────


class LogEntry(BaseModel):
    id: int
    email_id: Optional[int]
    timestamp: datetime
    event_type: str
    severity: str
    stage: Optional[str]
    message: str
    details: Optional[dict]
    source_ip: Optional[str]

    model_config = {"from_attributes": True}


# ─── Settings ────────────────────────────────────────────────────────────────


class ThresholdUpdate(BaseModel):
    threshold_suspicious: int = Field(ge=1, le=99)
    threshold_malicious: int = Field(ge=2, le=100)


# ─── ML Model ────────────────────────────────────────────────────────────────


class ModelMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: list[list[int]]
    training_samples: int
    test_samples: int
    top_features: list[dict]
    trained_at: Optional[str]
    dataset_source: str
