"""Security guard for the SOC Analyst Agent orchestrator.

Enforces authorization, destructive-action gating, data access control,
and per-action rate limiting before tool execution.

SOC-specific RBAC:
  - analyst  : can triage, enrich, correlate, view own alerts
  - lead     : analyst + contain, generate playbooks
  - manager  : lead + close incidents, approve containment
  - admin    : full access
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# RBAC definitions
# ---------------------------------------------------------------------------

# Permissions each role inherits (cumulative)
_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "analyst": frozenset(
        {
            "triage_alert",
            "enrich_ioc",
            "correlate_events",
            "query_siem",
            "view_alerts",
            "view_own_incidents",
        }
    ),
    "lead": frozenset(
        {
            "triage_alert",
            "enrich_ioc",
            "correlate_events",
            "query_siem",
            "view_alerts",
            "view_own_incidents",
            "generate_investigation",
            "contain_host",
            "contain_user",
            "view_all_incidents",
        }
    ),
    "manager": frozenset(
        {
            "triage_alert",
            "enrich_ioc",
            "correlate_events",
            "query_siem",
            "view_alerts",
            "view_own_incidents",
            "generate_investigation",
            "contain_host",
            "contain_user",
            "view_all_incidents",
            "create_incident_report",
            "close_incident",
            "approve_containment",
            "modify_playbook",
        }
    ),
    "admin": frozenset({"*"}),  # wildcard -- everything allowed
}

# Tools that map to specific permissions
_TOOL_PERMISSION_MAP: dict[str, str] = {
    "triage_alert": "triage_alert",
    "enrich_ioc": "enrich_ioc",
    "correlate_events": "correlate_events",
    "query_siem": "query_siem",
    "generate_investigation": "generate_investigation",
    "create_incident_report": "create_incident_report",
    "containment": "contain_host",
}

# Actions that require explicit approval (two-person rule)
_APPROVAL_REQUIRED: frozenset[str] = frozenset(
    {
        "contain_host",
        "contain_user",
        "close_incident",
    }
)


# ---------------------------------------------------------------------------
# Guard result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    reason: str
    requires_approval: bool = False
    approval_type: str = ""


# ---------------------------------------------------------------------------
# Per-action rate limiter (in-memory for simplicity; Redis in production)
# ---------------------------------------------------------------------------


class _ActionRateLimiter:
    """Simple in-memory sliding window rate limiter per (user, action)."""

    def __init__(self, default_limit: int = 50, window_seconds: int = 3600) -> None:
        self._limit = default_limit
        self._window = window_seconds
        # (user_id, action) -> list of timestamps
        self._buckets: dict[tuple[str, str], list[float]] = {}

    # Per-action overrides
    _ACTION_LIMITS: dict[str, int] = {
        "contain_host": 5,
        "contain_user": 5,
        "close_incident": 10,
        "create_incident_report": 20,
        "query_siem": 100,
    }

    def check(self, user_id: str, action: str) -> bool:
        """Return True if the action is within rate limits."""
        now = time.time()
        key = (user_id, action)
        limit = self._ACTION_LIMITS.get(action, self._limit)

        if key not in self._buckets:
            self._buckets[key] = []

        # Prune old entries
        cutoff = now - self._window
        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

        if len(self._buckets[key]) >= limit:
            return False

        self._buckets[key].append(now)
        return True


# ---------------------------------------------------------------------------
# Security Guard
# ---------------------------------------------------------------------------


class SecurityGuard:
    """Pre-execution security gate for the SOC Analyst Agent."""

    def __init__(self) -> None:
        self._rate_limiter = _ActionRateLimiter()

    async def authorize(
        self,
        *,
        user_id: str,
        user_role: str,
        action: str,
        tool_name: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> GuardResult:
        """Check whether the user is authorized to perform the action.

        Runs the following checks in order:
        1. Role-based permission check
        2. Data access control
        3. Destructive action gate
        4. Rate limit check
        """
        params = parameters or {}

        # 1. RBAC check
        rbac_result = self._check_rbac(user_role, tool_name, action)
        if not rbac_result.allowed:
            logger.warning(
                "guard_rbac_denied",
                user_id=user_id,
                role=user_role,
                tool=tool_name,
                action=action,
            )
            return rbac_result

        # 2. Data access control
        data_result = self._check_data_access(user_id, user_role, params)
        if not data_result.allowed:
            logger.warning(
                "guard_data_access_denied",
                user_id=user_id,
                reason=data_result.reason,
            )
            return data_result

        # 3. Destructive action gate
        destructive_result = self._check_destructive_action(
            user_role, tool_name, action
        )
        if not destructive_result.allowed:
            logger.info(
                "guard_approval_required",
                user_id=user_id,
                action=action,
                approval_type=destructive_result.approval_type,
            )
            return destructive_result

        # 4. Rate limit
        rate_ok = self._rate_limiter.check(user_id, action or tool_name)
        if not rate_ok:
            logger.warning(
                "guard_rate_limited",
                user_id=user_id,
                action=action or tool_name,
            )
            return GuardResult(
                allowed=False,
                reason=f"Rate limit exceeded for action '{action or tool_name}'. "
                "Please wait before retrying.",
            )

        logger.debug(
            "guard_authorized",
            user_id=user_id,
            role=user_role,
            tool=tool_name,
        )
        return GuardResult(allowed=True, reason="Authorized")

    # ------------------------------------------------------------------
    # RBAC
    # ------------------------------------------------------------------

    def _check_rbac(
        self, user_role: str, tool_name: str, action: str
    ) -> GuardResult:
        """Verify the user's role grants permission for the tool/action."""
        permissions = _ROLE_PERMISSIONS.get(user_role, frozenset())

        # Admin wildcard
        if "*" in permissions:
            return GuardResult(allowed=True, reason="Admin role -- full access")

        # Map tool name to required permission
        required = _TOOL_PERMISSION_MAP.get(tool_name, tool_name)
        if not required:
            required = action

        if required in permissions:
            return GuardResult(allowed=True, reason=f"Permission '{required}' granted to role '{user_role}'")

        return GuardResult(
            allowed=False,
            reason=f"Role '{user_role}' lacks permission '{required}'. "
            f"Required for tool '{tool_name}'. "
            "Contact your SOC lead for elevated access.",
        )

    # ------------------------------------------------------------------
    # Data access control
    # ------------------------------------------------------------------

    def _check_data_access(
        self,
        user_id: str,
        user_role: str,
        parameters: dict[str, Any],
    ) -> GuardResult:
        """Enforce data-level access restrictions.

        Analysts can only see alerts assigned to them or their team.
        Leads and above can see all alerts.
        """
        # If the request references a specific alert or incident,
        # check ownership (simplified -- production would query DB)
        alert_owner = parameters.get("alert_owner")
        incident_owner = parameters.get("incident_owner")

        if user_role == "analyst":
            if alert_owner and alert_owner != user_id:
                return GuardResult(
                    allowed=False,
                    reason=f"Analyst '{user_id}' cannot access alerts owned by '{alert_owner}'. "
                    "Request reassignment from your SOC lead.",
                )
            if incident_owner and incident_owner != user_id:
                return GuardResult(
                    allowed=False,
                    reason=f"Analyst '{user_id}' cannot access incidents owned by '{incident_owner}'.",
                )

        return GuardResult(allowed=True, reason="Data access permitted")

    # ------------------------------------------------------------------
    # Destructive action gate
    # ------------------------------------------------------------------

    def _check_destructive_action(
        self, user_role: str, tool_name: str, action: str
    ) -> GuardResult:
        """Gate containment and other destructive actions behind approval."""
        required_permission = _TOOL_PERMISSION_MAP.get(tool_name, action)

        if required_permission in _APPROVAL_REQUIRED:
            # Managers can self-approve; others need manager approval
            if user_role in ("manager", "admin"):
                return GuardResult(
                    allowed=True,
                    reason=f"Role '{user_role}' can self-approve '{required_permission}'",
                )

            return GuardResult(
                allowed=False,
                reason=f"Action '{required_permission}' requires manager approval. "
                "Escalate to your SOC manager for authorization.",
                requires_approval=True,
                approval_type="manager_approval",
            )

        return GuardResult(allowed=True, reason="Not a destructive action")
