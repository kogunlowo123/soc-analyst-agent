"""Main agent orchestrator.

Decomposes user requests into sub-tasks, routes them through
Planner -> Researcher / Executor -> Validator pipeline,
and maintains conversation state across turns.

State machine:  PLAN -> RESEARCH -> EXECUTE -> VALIDATE -> RESPOND
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from src.agent.orchestrator.executor import Executor
from src.agent.orchestrator.guard import SecurityGuard
from src.agent.orchestrator.planner import Planner, SubTask, TaskType
from src.agent.orchestrator.researcher import Researcher
from src.agent.orchestrator.validator import Validator, ValidationResult

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


class OrchestratorState(str, Enum):
    IDLE = "idle"
    PLAN = "plan"
    RESEARCH = "research"
    EXECUTE = "execute"
    VALIDATE = "validate"
    RESPOND = "respond"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Conversation state
# ---------------------------------------------------------------------------


@dataclass
class ConversationTurn:
    role: str  # "user" | "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationContext:
    conversation_id: str
    turns: list[ConversationTurn] = field(default_factory=list)
    active_investigation: dict[str, Any] = field(default_factory=dict)
    enrichment_cache: dict[str, Any] = field(default_factory=dict)

    def add_turn(self, role: str, content: str, metadata: dict[str, Any] | None = None) -> None:
        self.turns.append(
            ConversationTurn(role=role, content=content, metadata=metadata or {})
        )

    def recent_turns(self, n: int = 10) -> list[ConversationTurn]:
        return self.turns[-n:]


# ---------------------------------------------------------------------------
# Orchestration result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrchestrationResult:
    response: str
    sources: list[dict[str, Any]]
    tool_results: list[dict[str, Any]]
    validation: ValidationResult | None
    state_trace: list[str]
    latency_ms: float


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AgentOrchestrator:
    """Top-level orchestrator that drives the SOC analyst investigation pipeline.

    Usage::

        orch = AgentOrchestrator()
        result = await orch.process(
            message="Investigate alert ALT-12345",
            user_id="analyst-1",
            conversation_id="conv-abc",
        )
    """

    def __init__(self) -> None:
        self._planner = Planner()
        self._researcher = Researcher()
        self._executor = Executor()
        self._validator = Validator()
        self._guard = SecurityGuard()
        self._conversations: dict[str, ConversationContext] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def process(
        self,
        *,
        message: str,
        user_id: str,
        user_role: str = "analyst",
        conversation_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> OrchestrationResult:
        """Process a single user message through the full pipeline."""
        start = time.time()
        conv_id = conversation_id or str(uuid.uuid4())
        state_trace: list[str] = []
        current_state = OrchestratorState.IDLE

        # Get or create conversation context
        conv = self._get_or_create_conversation(conv_id)
        conv.add_turn("user", message)

        accumulated_sources: list[dict[str, Any]] = []
        accumulated_tool_results: list[dict[str, Any]] = []
        final_response = ""
        validation_result: ValidationResult | None = None

        try:
            # ---- PLAN ----
            current_state = OrchestratorState.PLAN
            state_trace.append(current_state.value)
            logger.info("orchestrator_phase", phase="plan", conversation_id=conv_id)

            plan = await self._planner.decompose(
                message=message,
                conversation_history=[
                    {"role": t.role, "content": t.content}
                    for t in conv.recent_turns(10)
                ],
                context=context,
            )

            if not plan:
                # Simple query -- answer directly
                current_state = OrchestratorState.RESPOND
                state_trace.append(current_state.value)
                final_response = await self._generate_direct_response(message, conv)
            else:
                # Process each sub-task in dependency order
                task_results: dict[str, Any] = {}

                for task in plan:
                    # Check dependencies are met
                    if not self._dependencies_met(task, task_results):
                        logger.warning(
                            "task_dependency_unmet",
                            task_id=task.task_id,
                            deps=task.dependencies,
                        )
                        continue

                    if task.task_type == TaskType.RESEARCH:
                        # ---- RESEARCH ----
                        current_state = OrchestratorState.RESEARCH
                        state_trace.append(current_state.value)

                        research_result = await self._researcher.investigate(
                            query=task.description,
                            prior_results=task_results,
                            enrichment_cache=conv.enrichment_cache,
                        )
                        task_results[task.task_id] = research_result
                        accumulated_sources.extend(research_result.get("sources", []))
                        # Cache enrichment results for multi-turn
                        if "enrichments" in research_result:
                            conv.enrichment_cache.update(research_result["enrichments"])

                    elif task.task_type == TaskType.EXECUTE:
                        # ---- SECURITY CHECK ----
                        guard_result = await self._guard.authorize(
                            user_id=user_id,
                            user_role=user_role,
                            action=task.description,
                            tool_name=task.metadata.get("tool", ""),
                            parameters=task.metadata.get("parameters", {}),
                        )
                        if not guard_result.allowed:
                            logger.warning(
                                "action_blocked_by_guard",
                                task_id=task.task_id,
                                reason=guard_result.reason,
                            )
                            task_results[task.task_id] = {
                                "blocked": True,
                                "reason": guard_result.reason,
                            }
                            continue

                        # ---- EXECUTE ----
                        current_state = OrchestratorState.EXECUTE
                        state_trace.append(current_state.value)

                        exec_result = await self._executor.execute(
                            tool_name=task.metadata.get("tool", ""),
                            parameters=task.metadata.get("parameters", {}),
                            task_description=task.description,
                        )
                        task_results[task.task_id] = exec_result
                        accumulated_tool_results.append(exec_result)

                    elif task.task_type == TaskType.RESPOND:
                        # Direct LLM response sub-task
                        task_results[task.task_id] = {
                            "type": "respond",
                            "content": task.description,
                        }

                # ---- VALIDATE ----
                current_state = OrchestratorState.VALIDATE
                state_trace.append(current_state.value)

                validation_result = await self._validator.validate(
                    task_results=task_results,
                    original_query=message,
                    sources=accumulated_sources,
                )
                if not validation_result.passed:
                    logger.warning(
                        "validation_failed",
                        issues=validation_result.issues,
                    )

                # ---- RESPOND ----
                current_state = OrchestratorState.RESPOND
                state_trace.append(current_state.value)

                final_response = await self._synthesize_response(
                    message=message,
                    task_results=task_results,
                    validation=validation_result,
                    conversation=conv,
                )

        except Exception as exc:
            current_state = OrchestratorState.ERROR
            state_trace.append(current_state.value)
            logger.error(
                "orchestrator_error",
                conversation_id=conv_id,
                state=current_state.value,
                error=str(exc),
            )
            final_response = (
                f"An error occurred during processing: {exc}. "
                "Please try again or contact your SOC lead."
            )

        # Store assistant turn
        conv.add_turn("assistant", final_response, metadata={"state_trace": state_trace})

        latency_ms = (time.time() - start) * 1000
        logger.info(
            "orchestrator_complete",
            conversation_id=conv_id,
            latency_ms=round(latency_ms, 2),
            states=state_trace,
        )

        return OrchestrationResult(
            response=final_response,
            sources=accumulated_sources,
            tool_results=accumulated_tool_results,
            validation=validation_result,
            state_trace=state_trace,
            latency_ms=round(latency_ms, 2),
        )

    # ------------------------------------------------------------------
    # Conversation management
    # ------------------------------------------------------------------

    def _get_or_create_conversation(self, conv_id: str) -> ConversationContext:
        if conv_id not in self._conversations:
            self._conversations[conv_id] = ConversationContext(conversation_id=conv_id)
        return self._conversations[conv_id]

    def clear_conversation(self, conv_id: str) -> None:
        self._conversations.pop(conv_id, None)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dependencies_met(task: SubTask, results: dict[str, Any]) -> bool:
        return all(dep in results for dep in task.dependencies)

    async def _generate_direct_response(
        self, message: str, conv: ConversationContext
    ) -> str:
        """Handle simple queries that don't need decomposition."""
        from src.agent.prompts import SYSTEM_PROMPT

        history_text = "\n".join(
            f"{t.role}: {t.content}" for t in conv.recent_turns(5)
        )
        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Conversation history:\n{history_text}\n\n"
            f"User: {message}\n\n"
            "Provide a concise, helpful response."
        )
        # In production, call the LLM here
        return f"[Direct response to: {message}]"

    async def _synthesize_response(
        self,
        *,
        message: str,
        task_results: dict[str, Any],
        validation: ValidationResult,
        conversation: ConversationContext,
    ) -> str:
        """Combine all sub-task results into a coherent final response."""
        parts: list[str] = []

        for task_id, result in task_results.items():
            if isinstance(result, dict):
                if result.get("blocked"):
                    parts.append(
                        f"Action blocked: {result.get('reason', 'Insufficient permissions')}"
                    )
                elif result.get("type") == "research":
                    findings = result.get("findings", [])
                    if findings:
                        parts.append("Research findings:")
                        for f in findings:
                            parts.append(f"  - {f}")
                elif result.get("type") == "tool_execution":
                    parts.append(
                        f"Tool '{result.get('tool_name', 'unknown')}': "
                        f"{result.get('summary', str(result.get('result', '')))}"
                    )
                else:
                    parts.append(str(result))

        if not validation.passed:
            parts.append(
                "\nNote: Some findings could not be fully validated. "
                f"Issues: {'; '.join(validation.issues)}"
            )

        if parts:
            return "\n\n".join(parts)
        return f"Investigation complete for: {message}"
