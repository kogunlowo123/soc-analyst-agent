"""Central registry for all available SOC Analyst Agent tools.

Every tool is registered with metadata (name, category, permissions,
side-effect flag) and a JSON Schema for input validation.  The registry
handles discovery, input validation, permission checks, and auditable
execution.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import jsonschema
import structlog

logger = structlog.get_logger(__name__)


class ToolCategory(str, Enum):
    """Logical grouping of tools."""

    SIEM = "siem"
    THREAT_INTEL = "threat_intel"
    INCIDENT_MANAGEMENT = "incident_management"
    NOTIFICATION = "notification"
    INFRASTRUCTURE = "infrastructure"


@dataclass(frozen=True)
class ToolDefinition:
    """Immutable descriptor for a single tool."""

    name: str
    description: str
    category: ToolCategory
    input_schema: dict[str, Any]
    handler: Callable[..., Coroutine[Any, Any, dict[str, Any]]]
    required_permissions: frozenset[str] = field(default_factory=frozenset)
    side_effects: bool = False


@dataclass(frozen=True)
class ToolExecutionResult:
    """Immutable result envelope returned after tool execution."""

    tool_name: str
    success: bool
    data: dict[str, Any]
    error: str | None = None
    duration_ms: float = 0.0


class ToolPermissionError(Exception):
    """Raised when the caller lacks required permissions."""


class ToolNotFoundError(Exception):
    """Raised when a tool name is not in the registry."""


class ToolInputValidationError(Exception):
    """Raised when tool input fails JSON Schema validation."""


class ToolRegistry:
    """Thread-safe, category-aware registry of SOC tools.

    Usage::

        registry = ToolRegistry()
        registry.register(ToolDefinition(...))
        result = await registry.execute("query_splunk", params, user_ctx)
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(self, tool: ToolDefinition) -> None:
        """Register a tool.  Overwrites silently if name already exists."""
        async with self._lock:
            self._tools[tool.name] = tool
            logger.info(
                "tool_registered",
                name=tool.name,
                category=tool.category.value,
                side_effects=tool.side_effects,
            )

    def register_sync(self, tool: ToolDefinition) -> None:
        """Non-async registration for module-level setup."""
        self._tools[tool.name] = tool

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def get(self, name: str) -> ToolDefinition:
        """Return a tool by exact name or raise ``ToolNotFoundError``."""
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFoundError(f"Tool '{name}' is not registered") from exc

    def list_tools(self, category: ToolCategory | None = None) -> list[ToolDefinition]:
        """Return tools, optionally filtered by category."""
        if category is None:
            return list(self._tools.values())
        return [t for t in self._tools.values() if t.category == category]

    def list_names(self, category: ToolCategory | None = None) -> list[str]:
        """Return tool names, optionally filtered by category."""
        return [t.name for t in self.list_tools(category)]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(
        self,
        name: str,
        params: dict[str, Any],
        user_context: dict[str, Any] | None = None,
    ) -> ToolExecutionResult:
        """Validate input, check permissions, run the handler, and log."""
        tool = self.get(name)
        user_context = user_context or {}

        # --- permission check ---
        user_permissions: frozenset[str] = frozenset(
            user_context.get("permissions", [])
        )
        missing = tool.required_permissions - user_permissions
        if missing:
            logger.warning(
                "tool_permission_denied",
                tool=name,
                missing=sorted(missing),
                user=user_context.get("user_id"),
            )
            raise ToolPermissionError(
                f"Missing permissions for '{name}': {sorted(missing)}"
            )

        # --- input validation ---
        try:
            jsonschema.validate(instance=params, schema=tool.input_schema)
        except jsonschema.ValidationError as exc:
            logger.warning(
                "tool_input_invalid",
                tool=name,
                error=exc.message,
            )
            raise ToolInputValidationError(
                f"Invalid input for '{name}': {exc.message}"
            ) from exc

        # --- execute handler ---
        start = time.monotonic()
        try:
            data = await tool.handler(**params)
            duration_ms = (time.monotonic() - start) * 1_000
            logger.info(
                "tool_executed",
                tool=name,
                duration_ms=round(duration_ms, 2),
                user=user_context.get("user_id"),
            )
            return ToolExecutionResult(
                tool_name=name,
                success=True,
                data=data,
                duration_ms=round(duration_ms, 2),
            )
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1_000
            logger.error(
                "tool_execution_failed",
                tool=name,
                error=str(exc),
                duration_ms=round(duration_ms, 2),
            )
            return ToolExecutionResult(
                tool_name=name,
                success=False,
                data={},
                error=str(exc),
                duration_ms=round(duration_ms, 2),
            )
