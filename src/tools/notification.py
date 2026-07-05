"""Notification tools -- Slack, Microsoft Teams, e-mail, PagerDuty.

Each function builds the vendor-specific payload, sends the HTTP
request, and returns a success/failure envelope.
"""

from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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
# Slack
# ---------------------------------------------------------------------------

async def send_slack(
    channel: str,
    message: str,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Send a message to a Slack channel via webhook or Bot API.

    Environment:
        SLACK_WEBHOOK_URL   -- incoming-webhook URL (simple path)
        SLACK_BOT_TOKEN     -- xoxb-* token (preferred for richer messages)
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    bot_token = os.environ.get("SLACK_BOT_TOKEN", "")

    @_RETRY
    async def _via_webhook() -> dict[str, Any]:
        payload: dict[str, Any] = {"text": message, "channel": channel}
        if attachments:
            payload["attachments"] = attachments
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(webhook_url, json=payload)
            resp.raise_for_status()
            return {"channel": channel, "sent": True, "method": "webhook"}

    @_RETRY
    async def _via_bot() -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": channel, "text": message}
        if attachments:
            payload["attachments"] = attachments
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {bot_token}"},
                json=payload,
            )
            resp.raise_for_status()
            body = resp.json()
            if not body.get("ok"):
                raise RuntimeError(f"Slack API error: {body.get('error')}")
            return {"channel": channel, "sent": True, "method": "bot_api", "ts": body.get("ts")}

    try:
        if bot_token:
            result = await _via_bot()
        elif webhook_url:
            result = await _via_webhook()
        else:
            result = {"channel": channel, "sent": False, "error": "No Slack credentials configured"}
        logger.info("slack_message_sent", channel=channel, sent=result.get("sent"))
        return result
    except Exception as exc:
        logger.error("slack_send_failed", channel=channel, error=str(exc))
        return {"channel": channel, "sent": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Microsoft Teams
# ---------------------------------------------------------------------------

async def send_teams(
    channel: str,
    message: str,
    card: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send a message to a Microsoft Teams channel via webhook.

    Environment:
        TEAMS_WEBHOOK_URL -- the incoming-webhook connector URL
    """
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if not webhook_url:
        return {"channel": channel, "sent": False, "error": "TEAMS_WEBHOOK_URL not configured"}

    if card:
        payload = card
    else:
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": message[:100],
            "themeColor": "0076D7",
            "title": "SOC Analyst Agent Alert",
            "sections": [
                {
                    "activityTitle": channel,
                    "text": message,
                }
            ],
        }

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(webhook_url, json=payload)
            resp.raise_for_status()
            return {"channel": channel, "sent": True}

    try:
        result = await _dispatch()
        logger.info("teams_message_sent", channel=channel)
        return result
    except Exception as exc:
        logger.error("teams_send_failed", channel=channel, error=str(exc))
        return {"channel": channel, "sent": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# E-mail (SMTP or SendGrid)
# ---------------------------------------------------------------------------

async def send_email(
    to: str | list[str],
    subject: str,
    body: str,
    priority: str = "normal",
) -> dict[str, Any]:
    """Send an e-mail via SMTP or the SendGrid HTTP API.

    Environment (SMTP):
        SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM

    Environment (SendGrid):
        SENDGRID_API_KEY, SENDGRID_FROM
    """
    sendgrid_key = os.environ.get("SENDGRID_API_KEY", "")
    recipients = [to] if isinstance(to, str) else list(to)

    if sendgrid_key:
        return await _send_via_sendgrid(recipients, subject, body, priority, sendgrid_key)
    return await _send_via_smtp(recipients, subject, body, priority)


async def _send_via_sendgrid(
    recipients: list[str],
    subject: str,
    body: str,
    priority: str,
    api_key: str,
) -> dict[str, Any]:
    from_email = os.environ.get("SENDGRID_FROM", "soc-agent@corp.local")

    personalizations = [{"to": [{"email": r} for r in recipients]}]
    payload = {
        "personalizations": personalizations,
        "from": {"email": from_email},
        "subject": subject,
        "content": [{"type": "text/html", "value": body}],
    }
    if priority == "high":
        payload["headers"] = {"X-Priority": "1"}

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            return {"to": recipients, "sent": True, "method": "sendgrid"}

    try:
        result = await _dispatch()
        logger.info("email_sent", to=recipients, method="sendgrid")
        return result
    except Exception as exc:
        logger.error("email_sendgrid_failed", error=str(exc))
        return {"to": recipients, "sent": False, "error": str(exc)}


async def _send_via_smtp(
    recipients: list[str],
    subject: str,
    body: str,
    priority: str,
) -> dict[str, Any]:
    host = os.environ.get("SMTP_HOST", "localhost")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    from_addr = os.environ.get("SMTP_FROM", "soc-agent@corp.local")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    if priority == "high":
        msg["X-Priority"] = "1"
    msg.attach(MIMEText(body, "html"))

    try:
        import asyncio

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _smtp_send, host, port, user, password, from_addr, recipients, msg)
        logger.info("email_sent", to=recipients, method="smtp")
        return {"to": recipients, "sent": True, "method": "smtp"}
    except Exception as exc:
        logger.error("email_smtp_failed", error=str(exc))
        return {"to": recipients, "sent": False, "error": str(exc)}


def _smtp_send(
    host: str,
    port: int,
    user: str,
    password: str,
    from_addr: str,
    recipients: list[str],
    msg: MIMEMultipart,
) -> None:
    """Blocking SMTP send (run inside executor)."""
    with smtplib.SMTP(host, port, timeout=30) as server:
        server.ehlo()
        if port == 587:
            server.starttls()
        if user and password:
            server.login(user, password)
        server.sendmail(from_addr, recipients, msg.as_string())


# ---------------------------------------------------------------------------
# PagerDuty
# ---------------------------------------------------------------------------

async def send_pagerduty(
    severity: str,
    title: str,
    details: str,
    service: str | None = None,
) -> dict[str, Any]:
    """Create a PagerDuty incident via the Events API v2.

    Environment:
        PAGERDUTY_ROUTING_KEY -- integration key for the service
    """
    routing_key = os.environ.get("PAGERDUTY_ROUTING_KEY", "")
    if not routing_key:
        return {"sent": False, "error": "PAGERDUTY_ROUTING_KEY not configured"}

    valid_severities = {"critical", "error", "warning", "info"}
    pd_severity = severity.lower()
    if pd_severity not in valid_severities:
        pd_severity = "error"

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": title[:1024],
            "severity": pd_severity,
            "source": "soc-analyst-agent",
            "custom_details": {"details": details, "service": service or "default"},
        },
    }

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
            )
            resp.raise_for_status()
            body = resp.json()
            return {
                "sent": True,
                "dedup_key": body.get("dedup_key"),
                "status": body.get("status"),
            }

    try:
        result = await _dispatch()
        logger.info("pagerduty_event_sent", severity=pd_severity, title=title[:80])
        return result
    except Exception as exc:
        logger.error("pagerduty_send_failed", error=str(exc))
        return {"sent": False, "error": str(exc)}
