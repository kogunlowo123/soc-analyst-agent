"""Task decomposition planner for the SOC Analyst Agent.

Analyses user intent and decomposes complex requests into an ordered
list of sub-tasks, each tagged with a type (research / execute / respond)
and explicit dependency links.

SOC-specific: understands the canonical investigation workflow
  triage -> enrich -> correlate -> assess -> act
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence
from uuid import uuid4

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Sub-task types
# ---------------------------------------------------------------------------


class TaskType(str, Enum):
    RESEARCH = "research"  # RAG retrieval, threat intel, SIEM query
    EXECUTE = "execute"  # Tool invocation (create incident, send alert)
    RESPOND = "respond"  # Direct LLM-generated answer


# ---------------------------------------------------------------------------
# Sub-task model
# ---------------------------------------------------------------------------


@dataclass
class SubTask:
    task_id: str
    task_type: TaskType
    description: str
    dependencies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    priority: int = 0  # lower = higher priority


# ---------------------------------------------------------------------------
# Intent classifiers (keyword + pattern based)
# ---------------------------------------------------------------------------

_INTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\btriage\b", re.I), "triage"),
    (re.compile(r"\benrich\b|\bioc\b|\bindicator\b|\bthreat\s*intel", re.I), "enrich"),
    (re.compile(r"\bcorrelat\b|\bcross.?reference\b|\bsiem\b|\bquery\s+logs?\b", re.I), "correlate"),
    (re.compile(r"\bassess\b|\bseverity\b|\brisk\b|\bimpact\b", re.I), "assess"),
    (re.compile(r"\bcontain\b|\bisolat\b|\bblock\b|\bquarantine\b", re.I), "contain"),
    (re.compile(r"\bescalat\b|\bincident\b|\breport\b", re.I), "escalate"),
    (re.compile(r"\binvestigat\b|\banalyze?\b|\blook\s+into\b", re.I), "investigate"),
    (re.compile(r"\bplaybook\b|\bprocedure\b|\brunbook\b", re.I), "playbook"),
    (re.compile(r"\bmitre\b|\batt&?ck\b|\btechnique\b|\btactic\b", re.I), "mitre_mapping"),
    (re.compile(r"\balert\s+(?:id|#|number)?\s*[\w\-]+", re.I), "alert_lookup"),
]

# Maps detected intents to canonical SOC workflow stages
_INVESTIGATION_WORKFLOW: list[tuple[str, TaskType, str]] = [
    ("triage", TaskType.RESEARCH, "Validate alert and determine true/false positive"),
    ("enrich", TaskType.RESEARCH, "Enrich IOCs with threat intelligence"),
    ("correlate", TaskType.RESEARCH, "Correlate events across SIEM data sources"),
    ("assess", TaskType.RESEARCH, "Assess severity based on asset criticality and attack stage"),
    ("contain", TaskType.EXECUTE, "Execute containment actions if active threat"),
    ("escalate", TaskType.EXECUTE, "Create incident report and escalate"),
]


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


class Planner:
    """Decompose user messages into ordered sub-tasks for the orchestrator."""

    async def decompose(
        self,
        *,
        message: str,
        conversation_history: list[dict[str, str]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[SubTask]:
        """Analyse the user message and return an ordered plan.

        Returns an empty list if the message is simple enough to answer
        directly without decomposition.
        """
        intents = self._classify_intents(message)
        logger.info("planner_intents", intents=intents, message_preview=message[:100])

        if not intents:
            # Check for a full investigation request
            if self._is_full_investigation(message):
                return self._build_full_investigation_plan(message, context)
            # Simple question -- no decomposition needed
            return []

        return self._build_plan_from_intents(intents, message, context)

    # ------------------------------------------------------------------
    # Intent classification
    # ------------------------------------------------------------------

    def _classify_intents(self, message: str) -> list[str]:
        """Return a deduplicated, ordered list of detected intents."""
        seen: set[str] = set()
        result: list[str] = []
        for pattern, intent in _INTENT_PATTERNS:
            if pattern.search(message) and intent not in seen:
                seen.add(intent)
                result.append(intent)
        return result

    @staticmethod
    def _is_full_investigation(message: str) -> bool:
        """Detect requests for a complete investigation workflow."""
        full_patterns = [
            re.compile(r"\binvestigat\w*\s+alert\b", re.I),
            re.compile(r"\bfull\s+(?:analysis|investigation|triage)\b", re.I),
            re.compile(r"\bwhat\s+happened\s+with\b", re.I),
            re.compile(r"\bincident\s+response\b", re.I),
        ]
        return any(p.search(message) for p in full_patterns)

    # ------------------------------------------------------------------
    # Plan builders
    # ------------------------------------------------------------------

    def _build_full_investigation_plan(
        self, message: str, context: dict[str, Any] | None
    ) -> list[SubTask]:
        """Build the canonical SOC investigation pipeline:
        triage -> enrich -> correlate -> assess -> escalate
        """
        tasks: list[SubTask] = []
        prev_id: str | None = None

        for stage, task_type, description in _INVESTIGATION_WORKFLOW:
            task_id = f"{stage}_{uuid4().hex[:8]}"
            deps = [prev_id] if prev_id else []

            metadata: dict[str, Any] = {"stage": stage}
            if stage == "enrich":
                metadata["tool"] = "enrich_ioc"
                metadata["parameters"] = self._extract_iocs(message)
            elif stage == "correlate":
                metadata["tool"] = "correlate_events"
                metadata["parameters"] = {"query": message, "time_range": "24h"}
            elif stage == "contain":
                metadata["tool"] = "containment"
                metadata["requires_approval"] = True
            elif stage == "escalate":
                metadata["tool"] = "create_incident_report"

            if context:
                metadata["context"] = context

            tasks.append(
                SubTask(
                    task_id=task_id,
                    task_type=task_type,
                    description=f"{description} -- {message}",
                    dependencies=deps,
                    metadata=metadata,
                    priority=len(tasks),
                )
            )
            prev_id = task_id

        logger.info("plan_created", task_count=len(tasks), plan_type="full_investigation")
        return tasks

    def _build_plan_from_intents(
        self,
        intents: list[str],
        message: str,
        context: dict[str, Any] | None,
    ) -> list[SubTask]:
        """Build a plan from detected intents, preserving dependency order."""
        tasks: list[SubTask] = []
        prev_id: str | None = None

        for intent in intents:
            task_id = f"{intent}_{uuid4().hex[:8]}"
            task_type, description, metadata = self._intent_to_task(intent, message)

            if context:
                metadata["context"] = context

            deps = [prev_id] if prev_id else []
            tasks.append(
                SubTask(
                    task_id=task_id,
                    task_type=task_type,
                    description=description,
                    dependencies=deps,
                    metadata=metadata,
                    priority=len(tasks),
                )
            )
            prev_id = task_id

        logger.info(
            "plan_created",
            task_count=len(tasks),
            plan_type="intent_based",
            intents=intents,
        )
        return tasks

    @staticmethod
    def _intent_to_task(
        intent: str, message: str
    ) -> tuple[TaskType, str, dict[str, Any]]:
        """Map a single intent to task type, description, and metadata."""
        mapping: dict[str, tuple[TaskType, str, dict[str, Any]]] = {
            "triage": (
                TaskType.RESEARCH,
                f"Triage and validate: {message}",
                {"tool": "triage_alert", "parameters": {"query": message}},
            ),
            "enrich": (
                TaskType.RESEARCH,
                f"Enrich IOCs from: {message}",
                {"tool": "enrich_ioc"},
            ),
            "correlate": (
                TaskType.RESEARCH,
                f"Correlate events: {message}",
                {"tool": "correlate_events", "parameters": {"query": message, "time_range": "24h"}},
            ),
            "assess": (
                TaskType.RESEARCH,
                f"Assess severity and impact: {message}",
                {},
            ),
            "contain": (
                TaskType.EXECUTE,
                f"Execute containment: {message}",
                {"tool": "containment", "requires_approval": True},
            ),
            "escalate": (
                TaskType.EXECUTE,
                f"Escalate and create incident report: {message}",
                {"tool": "create_incident_report"},
            ),
            "investigate": (
                TaskType.RESEARCH,
                f"Full investigation: {message}",
                {},
            ),
            "playbook": (
                TaskType.RESEARCH,
                f"Generate investigation playbook: {message}",
                {"tool": "generate_investigation"},
            ),
            "mitre_mapping": (
                TaskType.RESEARCH,
                f"Map to MITRE ATT&CK: {message}",
                {},
            ),
            "alert_lookup": (
                TaskType.RESEARCH,
                f"Look up alert details: {message}",
                {"tool": "query_siem"},
            ),
        }
        return mapping.get(
            intent,
            (TaskType.RESPOND, f"Respond to: {message}", {}),
        )

    # ------------------------------------------------------------------
    # IOC extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_iocs(text: str) -> dict[str, list[str]]:
        """Extract IOC values from text for enrichment tasks."""
        iocs: dict[str, list[str]] = {
            "ips": [],
            "domains": [],
            "hashes": [],
            "emails": [],
        }
        # IPv4
        for m in re.finditer(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            text,
        ):
            iocs["ips"].append(m.group())

        # Domains
        for m in re.finditer(
            r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
            text,
            re.I,
        ):
            candidate = m.group()
            if "." in candidate and not candidate.replace(".", "").isdigit():
                iocs["domains"].append(candidate)

        # Hashes (MD5, SHA1, SHA256)
        for m in re.finditer(r"\b[a-fA-F0-9]{32,64}\b", text):
            val = m.group()
            if len(val) in (32, 40, 64):
                iocs["hashes"].append(val)

        # Emails
        for m in re.finditer(
            r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", text
        ):
            iocs["emails"].append(m.group())

        return {k: v for k, v in iocs.items() if v}
