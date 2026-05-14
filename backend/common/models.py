"""Pydantic models for Sentinel incident intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from typing import Any

from pydantic import BaseModel, Field, field_validator


Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class IncidentInput(BaseModel):
    """Incident/log payload from UI or API callers."""

    text: str = Field(min_length=1, max_length=50000)
    title: str | None = Field(default=None, max_length=200)
    source: str = Field(default="manual", max_length=100)

    @field_validator("text", mode="before")
    @classmethod
    def must_not_contain_script_injection(cls, v: object) -> object:
        """Hard-reject input that contains script tags or javascript: URIs.

        Runs before the log-format check so the user gets a clear rejection
        rather than a format error when the real problem is embedded markup.
        """
        from common.guardrails import detect_hard_xss  # noqa: PLC0415

        if not isinstance(v, str):
            return v
        hits = detect_hard_xss(v)
        if hits:
            joined = ", ".join(hits[:3])
            raise ValueError(
                f"Input contains embedded script or markup ({joined}). "
                "Remove HTML tags and script blocks — log data must not contain executable markup."
            )
        return v

    @field_validator("text", mode="before")
    @classmethod
    def must_be_log_format(cls, v: object) -> object:
        """Reject input that carries no log-format signals."""
        from common.guardrails import validate_log_format  # noqa: PLC0415

        if not isinstance(v, str):
            return v  # let the type system report this error
        valid, reasons = validate_log_format(v)
        if not valid:
            raise ValueError(" ".join(reasons))
        return v


class GuardrailReport(BaseModel):
    """Guardrail status for one incident run."""

    prompt_injection_detected: bool = False
    blocked_patterns: list[str] = Field(default_factory=list)
    xss_detected: bool = False
    xss_patterns_removed: list[str] = Field(default_factory=list)
    input_truncated: bool = False
    unsafe_content_removed: bool = False
    notes: list[str] = Field(default_factory=list)


class NormalizedIncident(BaseModel):
    """Sanitized incident with extracted evidence snippets."""

    normalized_text: str
    evidence_snippets: list[str] = Field(default_factory=list)
    guardrails: GuardrailReport


class IncidentSummary(BaseModel):
    """Summary and severity classification."""

    summary: str
    severity: Severity
    severity_reason: str


class RootCauseAnalysis(BaseModel):
    """Likely root cause with confidence and rationale."""

    likely_root_cause: str
    confidence: Confidence
    reasoning: str
    supporting_evidence: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    """Recommended actions and immediate checks."""

    recommended_actions: list[str] = Field(default_factory=list)
    next_checks: list[str] = Field(default_factory=list)
    risk_if_unresolved: str
    # LLM-assigned severity per action, parallel to recommended_actions / next_checks.
    # Pipeline pads any missing entries with the incident severity before seeding.
    recommended_severities: list[str] = Field(default_factory=list)
    check_severities: list[str] = Field(default_factory=list)


class IncidentAnalysis(BaseModel):
    """Combined output from all agents."""

    incident_id: str
    job_id: str
    summary: IncidentSummary
    root_cause: RootCauseAnalysis
    remediation: RemediationPlan
    guardrails: GuardrailReport
    models: dict[str, str]
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class JobCreateResponse(BaseModel):
    """Response when creating a pending job."""

    incident_id: str
    job_id: str
    status: str


class JobRunResponse(BaseModel):
    """Response when running analysis."""

    incident_id: str
    job_id: str
    status: str
    analysis: IncidentAnalysis | None = None
    error: str | None = None


class InvestigationStreamInput(BaseModel):
    """Payload to stream investigator output (for live RCA preview)."""

    summary: str
    normalized_text: str
    evidence_snippets: list[str] = Field(default_factory=list)


class ClarificationQuestion(BaseModel):
    """A targeted question to gather context for refining the remediation plan."""

    id: str
    question: str
    rationale: str
    kind: Literal["text", "yes_no", "choice"] = "text"
    options: list[str] | None = None


class ClarificationSet(BaseModel):
    """Set of clarification questions generated after initial analysis."""

    job_id: str
    questions: list[ClarificationQuestion]
    urgency: Literal["suggested", "required"] = "suggested"
    already_answered: bool = False


class ClarificationAnswers(BaseModel):
    """User-provided answers to clarification questions."""

    answers: dict[str, str]


class ActionUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    notes: str | None = None
    severity: str | None = None
    due_date: str | None = None


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]  # system turns are never accepted from clients
    content: str = Field(min_length=1, max_length=4000)


class ActionChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    history: list[ChatMessage] = Field(default_factory=list, max_length=100)


class FollowUpCreate(BaseModel):
    user_email: str
    remind_at: str  # ISO-8601 datetime
    action_id: str | None = None
    user_name: str | None = None
    message: str | None = None


class IntegrationCreate(BaseModel):
    type: str
    config: dict
    enabled: bool = True


class DigestRequest(BaseModel):
    days: int = 7


class RemediationFollowUpRequest(BaseModel):
    """Engineer-provided findings from working through remediation steps."""

    additional_context: str = Field(min_length=1, max_length=10000)
    anchor_action_id: str | None = None   # action that originated the findings


class ActionEvaluationRequest(BaseModel):
    """Engineer findings submitted against a specific remediation action."""

    findings: str = Field(min_length=1, max_length=10000)


class ActionEvaluationResult(BaseModel):
    """LLM verdict on whether engineer findings resolve a remediation action."""

    satisfied: bool
    response: str          # short explanation to show the engineer
    next_step: str | None = None  # sub-action text when not yet satisfied


class RemediationFollowUp(BaseModel):
    """Follow-up actions generated from engineer findings during active remediation."""

    followup_actions: list[str] = Field(default_factory=list)
    followup_severities: list[str] = Field(default_factory=list)
    followup_checks: list[str] = Field(default_factory=list)
    check_severities: list[str] = Field(default_factory=list)
    updated_risk: str = ""
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PostIncidentReview(BaseModel):
    """Structured post-incident review generated after remediation is complete."""

    job_id: str
    timeline: str
    what_went_wrong: str
    what_went_right: str
    action_summary: list[str] = Field(default_factory=list)
    prevention_steps: list[str] = Field(default_factory=list)
    lessons_learned: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IncidentResolveRequest(BaseModel):
    """Payload to mark an incident resolved."""

    resolution_notes: str | None = None
    status: Literal["open", "in_progress", "resolved"] = "resolved"

CompareVerdict = Literal["likely_same", "likely_different", "unclear"]


class IncidentCompareRequest(BaseModel):
    job_id_a: str = Field(min_length=1)
    job_id_b: str = Field(min_length=1)

    @field_validator("job_id_b", mode="after")
    @classmethod
    def ids_must_differ(cls, b: str, info) -> str:
        a = info.data.get("job_id_a")
        if a and b == a:
            raise ValueError("job_id_a and job_id_b must be different")
        return b


class IncidentCompareResult(BaseModel):
    job_id_a: str
    job_id_b: str
    verdict: CompareVerdict
    confidence: Confidence
    overlapping_symptoms: list[str] = Field(default_factory=list)
    divergences: list[str] = Field(default_factory=list)
    operator_next_steps: list[str] = Field(default_factory=list)
    notes: str = ""
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class LiveMonitorConfigUpdate(BaseModel):
    """Per-user CloudWatch monitoring settings for Live Incident Board."""

    enabled: bool = True
    log_groups: list[str] = Field(default_factory=list, max_length=50)
    lookback_minutes: int = Field(default=5, ge=1, le=60)
    error_threshold: int = Field(default=5, ge=1, le=100)


LiveProvider = Literal["gcp_cloud_logging", "aws_cloudwatch", "webhook", "opentelemetry"]
ServiceCriticality = Literal["low", "medium", "high", "critical"]


class LiveApplicationCreate(BaseModel):
    """A business application made of multiple services."""

    name: str = Field(min_length=1, max_length=160)
    environment: str = Field(default="production", min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=1000)
    enabled: bool = True


class LiveApplicationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    environment: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=1000)
    enabled: bool | None = None


class LiveServiceCreate(BaseModel):
    """One microservice that belongs to a live application."""

    name: str = Field(min_length=1, max_length=160)
    service_type: str = Field(default="service", max_length=80)
    criticality: ServiceCriticality = "medium"
    owner: str | None = Field(default=None, max_length=160)
    dependency_order: int = Field(default=0, ge=0, le=1000)
    metadata: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class LiveServiceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    service_type: str | None = Field(default=None, max_length=80)
    criticality: ServiceCriticality | None = None
    owner: str | None = Field(default=None, max_length=160)
    dependency_order: int | None = Field(default=None, ge=0, le=1000)
    metadata: dict[str, Any] | None = None
    enabled: bool | None = None


class LiveLogSourceCreate(BaseModel):
    """Provider-specific log source attached to one service."""

    provider: LiveProvider = "gcp_cloud_logging"
    source_type: str = Field(default="log", max_length=80)
    source_ref: str = Field(min_length=1, max_length=500)
    filter_query: str | None = Field(default=None, max_length=2000)
    enabled: bool = True


class LiveLogSourceUpdate(BaseModel):
    provider: LiveProvider | None = None
    source_type: str | None = Field(default=None, max_length=80)
    source_ref: str | None = Field(default=None, min_length=1, max_length=500)
    filter_query: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None


class LiveLogRecord(BaseModel):
    """Normalized log event accepted by Live Incident ingestion."""

    timestamp: str | None = None
    message: str = Field(min_length=1, max_length=10000)
    severity: str = Field(default="default", max_length=80)
    trace_id: str | None = Field(default=None, max_length=300)
    labels: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)


class LiveIngestRequest(BaseModel):
    """Provider-agnostic log ingestion payload for one service."""

    application_id: str = Field(min_length=1)
    service_id: str = Field(min_length=1)
    log_source_id: str | None = None
    provider: LiveProvider = "gcp_cloud_logging"
    records: list[LiveLogRecord] = Field(default_factory=list, min_length=1, max_length=200)


class LiveGcpPubSubIngestRequest(BaseModel):
    """GCP Pub/Sub push payload for Cloud Logging sinks."""

    application_id: str = Field(min_length=1)
    service_id: str | None = None
    log_source_id: str | None = None
    message: dict[str, Any]

class ReplayFrame(BaseModel):
    index: int
    stage: Literal["queued", "normalize", "summarize", "root_cause", "remediate", "completed", "failed"]
    title: str
    at: str | None = None
    detail: str | None = None
    snapshot: dict[str, Any] = Field(default_factory=dict)
    delta: dict[str, Any] = Field(default_factory=dict)


class ReplayResponse(BaseModel):
    job_id: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    frames: list[ReplayFrame] = Field(default_factory=list)


class ReplayExplainRequest(BaseModel):
    frame_index: int = Field(ge=0)


class ReplayExplainResponse(BaseModel):
    frame_index: int
    explanation: str
    confidence: Confidence
    evidence: list[str] = Field(default_factory=list)
