"""SOC Analyst Agent - Domain-Specific Schemas."""

from datetime import datetime
from uuid import UUID, uuid4
from typing import Any, Optional
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    """Chat request."""
    message: str
    conversation_id: UUID | None = None
    stream: bool = False
    context: dict[str, Any] | None = None


class ChatResponse(BaseModel):
    """Chat response."""
    message: str
    conversation_id: UUID
    message_id: UUID
    sources: list[dict[str, Any]] = []
    tool_results: list[dict[str, Any]] = []
    model: str
    latency_ms: float
    timestamp: datetime


class StreamChunk(BaseModel):
    """Streaming response chunk."""
    chunk: str
    conversation_id: UUID
    done: bool = False


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    uptime_seconds: float
    agent: str
    features: list[str]


class AlertTriage(BaseModel):
    """AlertTriage for SOC Analyst Agent."""
    alert_id: str
    verdict: str
    confidence: float
    mitre_tactic: str | None
    mitre_technique: str | None
    recommended_action: str


class IOCEnrichment(BaseModel):
    """IOCEnrichment for SOC Analyst Agent."""
    indicator: str
    indicator_type: str
    reputation: str
    threat_score: float
    sources: list[dict]
    related_campaigns: list[str]


class IncidentReport(BaseModel):
    """IncidentReport for SOC Analyst Agent."""
    incident_id: str
    severity: str
    summary: str
    affected_assets: list[str]
    timeline: list[dict]
    recommendations: list[str]

