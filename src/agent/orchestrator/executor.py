"""Tool execution sub-agent for the SOC Analyst Agent.

Receives tool call requests from the planner, validates parameters,
executes via the tool layer, handles errors and retries, and returns
structured results.

SOC-specific: can execute SIEM queries, create incidents, and send alerts.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

import structlog
from tenacity import (
    AsyncRetrying,
    RetryError,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Execution result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionResult:
    tool_name: str
    success: bool
    result: Any
    duration_ms: float
    error: str | None = None
    retries: int = 0
    summary: str = ""
    type: str = "tool_execution"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "tool_name": self.tool_name,
            "success": self.success,
            "result": self.result,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "retries": self.retries,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Parameter validation schemas
# ---------------------------------------------------------------------------

_TOOL_PARAM_SCHEMAS: dict[str, dict[str, Any]] = {
    "triage_alert": {
        "required": ["alert_id", "alert_data"],
        "types": {"alert_id": str, "alert_data": dict},
    },
    "enrich_ioc": {
        "required": ["indicator", "indicator_type"],
        "types": {"indicator": str, "indicator_type": str},
        "allowed_values": {
            "indicator_type": ["ip", "domain", "hash", "email", "url"],
        },
    },
    "correlate_events": {
        "required": ["query", "time_range", "data_sources"],
        "types": {"query": str, "time_range": str, "data_sources": list},
    },
    "query_siem": {
        "required": ["query", "index", "time_range"],
        "types": {"query": str, "index": str, "time_range": str},
    },
    "generate_investigation": {
        "required": ["alert_type", "context"],
        "types": {"alert_type": str, "context": dict},
    },
    "create_incident_report": {
        "required": ["alert_ids", "findings", "severity"],
        "types": {"alert_ids": list, "findings": dict, "severity": str},
        "allowed_values": {
            "severity": ["critical", "high", "medium", "low", "informational"],
        },
    },
}


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------


class Executor:
    """Execute tool calls with validation, error handling, and retry logic."""

    def __init__(
        self,
        max_retries: int = 3,
        retry_wait_min: float = 1.0,
        retry_wait_max: float = 10.0,
    ) -> None:
        self._max_retries = max_retries
        self._retry_wait_min = retry_wait_min
        self._retry_wait_max = retry_wait_max
        self._tool_registry: dict[str, Callable[..., Awaitable[Any]]] = {}
        self._register_default_tools()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute(
        self,
        *,
        tool_name: str,
        parameters: dict[str, Any],
        task_description: str = "",
    ) -> dict[str, Any]:
        """Validate, execute, and return structured result for a tool call."""
        start = time.time()
        retries_used = 0

        # 1. Validate parameters
        validation_error = self._validate_parameters(tool_name, parameters)
        if validation_error:
            logger.warning(
                "tool_param_validation_failed",
                tool=tool_name,
                error=validation_error,
            )
            return ExecutionResult(
                tool_name=tool_name,
                success=False,
                result=None,
                duration_ms=0,
                error=f"Parameter validation failed: {validation_error}",
                summary=f"Failed to execute {tool_name}: invalid parameters",
            ).to_dict()

        # 2. Resolve tool function
        tool_fn = self._resolve_tool(tool_name)
        if tool_fn is None:
            return ExecutionResult(
                tool_name=tool_name,
                success=False,
                result=None,
                duration_ms=0,
                error=f"Unknown tool: {tool_name}",
                summary=f"Tool '{tool_name}' not found in registry",
            ).to_dict()

        # 3. Execute with retry
        last_error: str | None = None
        result: Any = None

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self._max_retries),
                wait=wait_exponential(
                    min=self._retry_wait_min, max=self._retry_wait_max
                ),
                retry=retry_if_exception_type((ConnectionError, TimeoutError, OSError)),
                reraise=True,
            ):
                with attempt:
                    retries_used = attempt.retry_state.attempt_number - 1
                    logger.info(
                        "tool_executing",
                        tool=tool_name,
                        attempt=attempt.retry_state.attempt_number,
                    )
                    result = await tool_fn(**parameters)

        except RetryError as exc:
            last_error = f"All {self._max_retries} retries exhausted: {exc}"
            logger.error(
                "tool_execution_retries_exhausted",
                tool=tool_name,
                retries=self._max_retries,
            )
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.error(
                "tool_execution_failed",
                tool=tool_name,
                error=last_error,
                traceback=traceback.format_exc(),
            )

        duration_ms = (time.time() - start) * 1000
        success = last_error is None

        exec_result = ExecutionResult(
            tool_name=tool_name,
            success=success,
            result=result,
            duration_ms=round(duration_ms, 2),
            error=last_error,
            retries=retries_used,
            summary=self._build_summary(tool_name, result, success),
        )

        logger.info(
            "tool_execution_complete",
            tool=tool_name,
            success=success,
            duration_ms=exec_result.duration_ms,
            retries=retries_used,
        )

        return exec_result.to_dict()

    def register_tool(
        self, name: str, fn: Callable[..., Awaitable[Any]]
    ) -> None:
        """Register a new tool function."""
        self._tool_registry[name] = fn

    # ------------------------------------------------------------------
    # Parameter validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_parameters(
        tool_name: str, parameters: dict[str, Any]
    ) -> str | None:
        """Validate parameters against the schema. Returns error string or None."""
        schema = _TOOL_PARAM_SCHEMAS.get(tool_name)
        if schema is None:
            # No schema defined -- allow through
            return None

        # Check required fields
        for req in schema.get("required", []):
            if req not in parameters:
                return f"Missing required parameter: {req}"

        # Check types
        type_checks = schema.get("types", {})
        for param_name, expected_type in type_checks.items():
            if param_name in parameters:
                value = parameters[param_name]
                if not isinstance(value, expected_type):
                    return (
                        f"Parameter '{param_name}' expected {expected_type.__name__}, "
                        f"got {type(value).__name__}"
                    )

        # Check allowed values
        allowed = schema.get("allowed_values", {})
        for param_name, valid_values in allowed.items():
            if param_name in parameters:
                value = parameters[param_name]
                if value not in valid_values:
                    return (
                        f"Parameter '{param_name}' value '{value}' not in "
                        f"allowed values: {valid_values}"
                    )

        return None

    # ------------------------------------------------------------------
    # Tool resolution
    # ------------------------------------------------------------------

    def _resolve_tool(self, tool_name: str) -> Callable[..., Awaitable[Any]] | None:
        """Look up a tool function by name."""
        return self._tool_registry.get(tool_name)

    def _register_default_tools(self) -> None:
        """Register the built-in SOC analyst tools."""
        from src.agent.tools import AgentTools

        self._tool_registry = {
            "triage_alert": AgentTools.triage_alert,
            "enrich_ioc": AgentTools.enrich_ioc,
            "correlate_events": AgentTools.correlate_events,
            "query_siem": AgentTools.query_siem,
            "generate_investigation": AgentTools.generate_investigation,
            "create_incident_report": AgentTools.create_incident_report,
        }

    # ------------------------------------------------------------------
    # Result summarisation
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(tool_name: str, result: Any, success: bool) -> str:
        """Build a human-readable summary of the tool execution."""
        if not success:
            return f"Tool '{tool_name}' execution failed"

        if isinstance(result, dict):
            status = result.get("status", "completed")
            tool_result = result.get("result", "")
            if isinstance(tool_result, str) and len(tool_result) > 200:
                tool_result = tool_result[:200] + "..."
            return f"Tool '{tool_name}' {status}: {tool_result}"

        return f"Tool '{tool_name}' completed successfully"
