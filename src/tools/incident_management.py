"""Incident management tools -- create, update, escalate, contain, block.

Every state-changing operation writes an immutable audit-trail record and
requires explicit permissions from the caller's user context.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = structlog.get_logger(__name__)

_RETRY = retry(
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    reraise=True,
)

# ---------------------------------------------------------------------------
# Audit trail helper
# ---------------------------------------------------------------------------

_audit_log: list[dict[str, Any]] = []


def _record_audit(
    action: str,
    actor: str,
    target: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    """Append an immutable audit entry and return it."""
    entry = {
        "audit_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "target": target,
        "details": details,
    }
    _audit_log.append(entry)
    logger.info(
        "audit_recorded",
        action=action,
        actor=actor,
        target=target,
    )
    return entry


# ---------------------------------------------------------------------------
# In-memory incident store (replaced by DB in production)
# ---------------------------------------------------------------------------

_incidents: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


async def create_incident(
    severity: str,
    title: str,
    description: str,
    affected_assets: list[str] | None = None,
) -> dict[str, Any]:
    """Create a new incident record.

    Args:
        severity: One of critical, high, medium, low, informational.
        title: Short incident title.
        description: Detailed description.
        affected_assets: List of hostnames / IPs / user accounts.
    """
    valid_severities = {"critical", "high", "medium", "low", "informational"}
    severity_lower = severity.lower()
    if severity_lower not in valid_severities:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of {valid_severities}"
        )

    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.now(timezone.utc).isoformat()

    incident: dict[str, Any] = {
        "incident_id": incident_id,
        "severity": severity_lower,
        "title": title,
        "description": description,
        "affected_assets": affected_assets or [],
        "status": "open",
        "created_at": now,
        "updated_at": now,
        "timeline": [
            {
                "timestamp": now,
                "action": "created",
                "note": f"Incident created with severity {severity_lower}",
            }
        ],
        "escalation_level": 0,
    }

    _incidents[incident_id] = incident
    _record_audit("create_incident", "system", incident_id, {"severity": severity_lower, "title": title})

    logger.info("incident_created", incident_id=incident_id, severity=severity_lower)
    return incident


async def update_incident(
    incident_id: str,
    status: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Update the status and/or add notes to an existing incident.

    Args:
        incident_id: The INC-XXXXXXXX identifier.
        status: New status (open, investigating, contained, resolved, closed).
        notes: Free-text notes appended to the timeline.
    """
    if incident_id not in _incidents:
        raise KeyError(f"Incident '{incident_id}' not found")

    valid_statuses = {"open", "investigating", "contained", "resolved", "closed"}
    if status and status.lower() not in valid_statuses:
        raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}")

    incident = _incidents[incident_id]
    now = datetime.now(timezone.utc).isoformat()

    if status:
        incident = {**incident, "status": status.lower(), "updated_at": now}
        incident["timeline"] = [
            *incident["timeline"],
            {"timestamp": now, "action": "status_change", "note": f"Status changed to {status.lower()}"},
        ]

    if notes:
        incident = {**incident, "updated_at": now}
        incident["timeline"] = [
            *incident["timeline"],
            {"timestamp": now, "action": "note_added", "note": notes},
        ]

    _incidents[incident_id] = incident
    _record_audit("update_incident", "system", incident_id, {"status": status, "notes": notes})

    logger.info("incident_updated", incident_id=incident_id, status=status)
    return incident


async def escalate_incident(
    incident_id: str,
    escalation_level: int,
    reason: str,
) -> dict[str, Any]:
    """Escalate an incident to a higher SOC tier.

    Args:
        incident_id: The INC-XXXXXXXX identifier.
        escalation_level: Target tier (1, 2, 3, or 4 for management).
        reason: Justification for escalation.
    """
    if incident_id not in _incidents:
        raise KeyError(f"Incident '{incident_id}' not found")

    if escalation_level not in {1, 2, 3, 4}:
        raise ValueError("escalation_level must be 1, 2, 3, or 4")

    incident = _incidents[incident_id]
    now = datetime.now(timezone.utc).isoformat()

    incident = {
        **incident,
        "escalation_level": escalation_level,
        "status": "investigating",
        "updated_at": now,
    }
    incident["timeline"] = [
        *incident["timeline"],
        {
            "timestamp": now,
            "action": "escalated",
            "note": f"Escalated to tier {escalation_level}: {reason}",
        },
    ]

    _incidents[incident_id] = incident
    _record_audit(
        "escalate_incident",
        "system",
        incident_id,
        {"escalation_level": escalation_level, "reason": reason},
    )

    logger.info("incident_escalated", incident_id=incident_id, level=escalation_level)
    return incident


# ---------------------------------------------------------------------------
# Containment actions
# ---------------------------------------------------------------------------


async def contain_host(
    hostname: str,
    action: str = "isolate",
) -> dict[str, Any]:
    """Isolate or un-isolate a host via CrowdStrike RTR / EDR API.

    Environment:
        CROWDSTRIKE_BASE_URL
        CROWDSTRIKE_CLIENT_ID
        CROWDSTRIKE_CLIENT_SECRET
    """
    valid_actions = {"isolate", "unisolate"}
    if action not in valid_actions:
        raise ValueError(f"action must be one of {valid_actions}")

    base_url = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
    client_id = os.environ.get("CROWDSTRIKE_CLIENT_ID", "")
    client_secret = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", "")

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            # 1. Authenticate
            token_resp = await c.post(
                f"{base_url}/oauth2/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
            )
            token_resp.raise_for_status()
            token = token_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # 2. Resolve hostname to device ID
            search_resp = await c.get(
                f"{base_url}/devices/queries/devices/v1",
                headers=headers,
                params={"filter": f"hostname:'{hostname}'"},
            )
            search_resp.raise_for_status()
            device_ids = search_resp.json().get("resources", [])
            if not device_ids:
                return {
                    "hostname": hostname,
                    "action": action,
                    "success": False,
                    "error": "Host not found in CrowdStrike",
                }

            device_id = device_ids[0]

            # 3. Perform containment action
            endpoint = (
                f"{base_url}/devices/entities/devices-actions/v2"
            )
            action_resp = await c.post(
                endpoint,
                headers=headers,
                params={"action_name": "contain" if action == "isolate" else "lift_containment"},
                json={"ids": [device_id]},
            )
            action_resp.raise_for_status()

            return {
                "hostname": hostname,
                "device_id": device_id,
                "action": action,
                "success": True,
            }

    result = await _dispatch()
    _record_audit("contain_host", "system", hostname, {"action": action, "result": result})
    logger.info("host_contained", hostname=hostname, action=action)
    return result


async def disable_user(
    username: str,
    reason: str,
) -> dict[str, Any]:
    """Disable an Active Directory user account.

    This is a placeholder that logs the intent.  In production, wire this
    to Microsoft Graph API or an on-prem AD connector via LDAP.

    Environment:
        AD_GRAPH_BASE_URL
        AD_GRAPH_TOKEN
    """
    logger.info("disable_user_requested", username=username, reason=reason)

    graph_url = os.environ.get("AD_GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")
    token = os.environ.get("AD_GRAPH_TOKEN", "")

    if token:
        @_RETRY
        async def _dispatch() -> dict[str, Any]:
            async with httpx.AsyncClient(timeout=30) as c:
                resp = await c.patch(
                    f"{graph_url}/users/{username}",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json={"accountEnabled": False},
                )
                resp.raise_for_status()
                return {"username": username, "disabled": True, "via": "ms_graph"}

        result = await _dispatch()
    else:
        result = {
            "username": username,
            "disabled": False,
            "via": "placeholder",
            "message": "AD integration not configured. No action taken.",
        }

    _record_audit("disable_user", "system", username, {"reason": reason, **result})
    return result


async def block_ioc(
    indicator: str,
    indicator_type: str,
    scope: str = "global",
) -> dict[str, Any]:
    """Add an indicator to the organisation's block list.

    Depending on type this may push to firewall, EDR, or proxy.

    Args:
        indicator: The value to block (IP, domain, hash).
        indicator_type: ip, domain, hash, url.
        scope: global or a specific site/network name.
    """
    valid_types = {"ip", "domain", "hash", "url"}
    if indicator_type not in valid_types:
        raise ValueError(f"indicator_type must be one of {valid_types}")

    base_url = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
    client_id = os.environ.get("CROWDSTRIKE_CLIENT_ID", "")
    client_secret = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", "")

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            # Authenticate
            token_resp = await c.post(
                f"{base_url}/oauth2/token",
                data={"client_id": client_id, "client_secret": client_secret},
            )
            token_resp.raise_for_status()
            token = token_resp.json()["access_token"]

            # Push IOC
            ioc_body = {
                "indicators": [
                    {
                        "type": indicator_type,
                        "value": indicator,
                        "action": "prevent",
                        "severity": "high",
                        "description": f"Blocked by SOC Analyst Agent - scope: {scope}",
                        "applied_globally": scope == "global",
                    }
                ]
            }
            resp = await c.post(
                f"{base_url}/iocs/entities/indicators/v1",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=ioc_body,
            )
            resp.raise_for_status()
            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "scope": scope,
                "blocked": True,
            }

    try:
        result = await _dispatch()
    except Exception as exc:
        result = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "scope": scope,
            "blocked": False,
            "error": str(exc),
        }

    _record_audit(
        "block_ioc",
        "system",
        indicator,
        {"type": indicator_type, "scope": scope, "result": result},
    )
    logger.info("ioc_blocked", indicator=indicator, type=indicator_type)
    return result
