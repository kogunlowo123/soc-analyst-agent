"""SIEM integration tools -- Splunk, Elastic, Microsoft Sentinel.

Each function builds the actual HTTP request, handles pagination and
auth, parses the JSON response, and returns structured results.
Connection config is read from environment variables.
"""

from __future__ import annotations

import os
import time
from typing import Any
from urllib.parse import quote

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Retry decorator for transient HTTP errors
# ---------------------------------------------------------------------------
_RETRY = retry(
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)


# ---------------------------------------------------------------------------
# Splunk
# ---------------------------------------------------------------------------
async def query_splunk(
    query_spl: str,
    time_range: str = "-24h",
    index: str = "main",
) -> dict[str, Any]:
    """Execute an SPL query against the Splunk REST API.

    Environment:
        SPLUNK_BASE_URL   -- e.g. https://splunk.corp.local:8089
        SPLUNK_TOKEN      -- bearer token
        SPLUNK_VERIFY_SSL -- "true" / "false" (default true)
    """
    base_url = os.environ.get("SPLUNK_BASE_URL", "https://localhost:8089")
    token = os.environ.get("SPLUNK_TOKEN", "")
    verify = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "true"

    full_spl = f"search index={index} {query_spl} earliest={time_range}"
    logger.info("splunk_query_start", spl=full_spl[:200])

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            verify=verify,
            timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=10.0),
        ) as client:
            # 1. Create a search job
            create_resp = await client.post(
                "/services/search/jobs",
                data={
                    "search": full_spl,
                    "output_mode": "json",
                    "earliest_time": time_range,
                    "exec_mode": "normal",
                },
            )
            create_resp.raise_for_status()
            sid = create_resp.json().get("sid", "")

            # 2. Poll until the job is done
            for _ in range(60):
                status_resp = await client.get(
                    f"/services/search/jobs/{sid}",
                    params={"output_mode": "json"},
                )
                status_resp.raise_for_status()
                entry = status_resp.json().get("entry", [{}])[0]
                content = entry.get("content", {})
                if content.get("isDone"):
                    break
                await _async_sleep(2)

            # 3. Fetch paginated results
            all_results: list[dict[str, Any]] = []
            offset = 0
            page_size = 1000
            while True:
                results_resp = await client.get(
                    f"/services/search/jobs/{sid}/results",
                    params={
                        "output_mode": "json",
                        "count": page_size,
                        "offset": offset,
                    },
                )
                results_resp.raise_for_status()
                page = results_resp.json().get("results", [])
                if not page:
                    break
                all_results.extend(page)
                offset += page_size

            return {
                "siem": "splunk",
                "query": full_spl,
                "result_count": len(all_results),
                "results": all_results[:500],
                "sid": sid,
            }

    return await _dispatch()


# ---------------------------------------------------------------------------
# Elastic SIEM
# ---------------------------------------------------------------------------
async def query_elastic(
    query_kql: str,
    time_range: str = "now-24h",
    index: str = ".siem-signals-*",
) -> dict[str, Any]:
    """Execute a KQL query against Elastic Security (Elasticsearch).

    Environment:
        ELASTIC_BASE_URL -- e.g. https://elastic.corp.local:9200
        ELASTIC_API_KEY  -- base-64 encoded API key
    """
    base_url = os.environ.get("ELASTIC_BASE_URL", "https://localhost:9200")
    api_key = os.environ.get("ELASTIC_API_KEY", "")

    logger.info("elastic_query_start", kql=query_kql[:200], index=index)

    body: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": query_kql}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_range,
                                "lte": "now",
                            }
                        }
                    },
                ],
            }
        },
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers={
                "Authorization": f"ApiKey {api_key}",
                "Content-Type": "application/json",
            },
            verify=True,
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
        ) as client:
            resp = await client.post(f"/{index}/_search", json=body)
            resp.raise_for_status()
            data = resp.json()

            hits = data.get("hits", {})
            total = hits.get("total", {}).get("value", 0)
            results = [h.get("_source", {}) for h in hits.get("hits", [])]

            return {
                "siem": "elastic",
                "query": query_kql,
                "result_count": total,
                "results": results,
            }

    return await _dispatch()


# ---------------------------------------------------------------------------
# Microsoft Sentinel
# ---------------------------------------------------------------------------
async def query_sentinel(
    query_kql: str,
    time_range: str = "P1D",
    workspace: str | None = None,
) -> dict[str, Any]:
    """Execute a KQL query against Microsoft Sentinel via Azure Monitor.

    Environment:
        SENTINEL_WORKSPACE_ID  -- Log Analytics workspace ID
        AZURE_TENANT_ID
        AZURE_CLIENT_ID
        AZURE_CLIENT_SECRET
    """
    workspace_id = workspace or os.environ.get("SENTINEL_WORKSPACE_ID", "")
    tenant_id = os.environ.get("AZURE_TENANT_ID", "")
    client_id = os.environ.get("AZURE_CLIENT_ID", "")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")

    logger.info("sentinel_query_start", kql=query_kql[:200], workspace=workspace_id)

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=10.0),
        ) as client:
            # 1. Obtain an Azure AD token
            token_resp = await client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://api.loganalytics.io/.default",
                    "grant_type": "client_credentials",
                },
            )
            token_resp.raise_for_status()
            access_token = token_resp.json()["access_token"]

            # 2. Run the KQL query
            query_resp = await client.post(
                f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"query": query_kql, "timespan": time_range},
            )
            query_resp.raise_for_status()
            data = query_resp.json()

            tables = data.get("tables", [])
            results: list[dict[str, Any]] = []
            for table in tables:
                columns = [c["name"] for c in table.get("columns", [])]
                for row in table.get("rows", []):
                    results.append(dict(zip(columns, row)))

            return {
                "siem": "sentinel",
                "query": query_kql,
                "result_count": len(results),
                "results": results[:500],
            }

    return await _dispatch()


# ---------------------------------------------------------------------------
# Natural-language to SIEM query translation
# ---------------------------------------------------------------------------
async def natural_language_to_siem(
    nl_query: str,
    siem_type: str = "splunk",
) -> dict[str, Any]:
    """Convert a natural-language question into SPL or KQL.

    This is a deterministic template-based translator for common patterns.
    For complex queries the LLM layer should be invoked instead.
    """
    siem_type = siem_type.lower()
    templates: dict[str, dict[str, str]] = {
        "splunk": {
            "failed_login": 'index=main sourcetype=auth action=failure | stats count by src_ip, user | sort -count',
            "brute_force": 'index=main sourcetype=auth action=failure | stats count by src_ip | where count > 5',
            "malware_detected": 'index=main sourcetype=av action=blocked | table _time, dest, file_name, signature',
            "dns_anomaly": 'index=main sourcetype=dns | stats count by query | where count > 100',
            "lateral_movement": 'index=main sourcetype=wineventlog EventCode=4624 Logon_Type=3 | stats count by src_ip, dest',
        },
        "elastic": {
            "failed_login": 'event.action:"authentication_failure" | sort @timestamp desc',
            "brute_force": 'event.action:"authentication_failure" AND source.ip:*',
            "malware_detected": 'event.category:"malware" AND event.action:"blocked"',
            "dns_anomaly": 'dns.question.name:* AND event.category:"dns"',
            "lateral_movement": 'event.code:"4624" AND winlog.event_data.LogonType:"3"',
        },
        "sentinel": {
            "failed_login": "SigninLogs | where ResultType != '0' | summarize count() by IPAddress, UserPrincipalName",
            "brute_force": "SigninLogs | where ResultType != '0' | summarize FailedCount=count() by IPAddress | where FailedCount > 5",
            "malware_detected": "SecurityAlert | where AlertName contains 'malware'",
            "dns_anomaly": "DnsEvents | summarize QueryCount=count() by Name | where QueryCount > 100",
            "lateral_movement": "SecurityEvent | where EventID == 4624 and LogonType == 3 | summarize count() by IpAddress, Computer",
        },
    }

    nl_lower = nl_query.lower()
    best_match: str | None = None
    best_score = 0
    category_keywords: dict[str, list[str]] = {
        "failed_login": ["failed login", "login failure", "authentication fail", "sign-in fail"],
        "brute_force": ["brute force", "password spray", "multiple failed", "repeated failure"],
        "malware_detected": ["malware", "virus", "trojan", "ransomware", "antivirus"],
        "dns_anomaly": ["dns", "domain lookup", "dns tunnel", "dns exfil"],
        "lateral_movement": ["lateral movement", "pass the hash", "remote login", "logon type 3"],
    }

    for category, keywords in category_keywords.items():
        for kw in keywords:
            if kw in nl_lower:
                score = len(kw)
                if score > best_score:
                    best_score = score
                    best_match = category

    siem_templates = templates.get(siem_type, templates["splunk"])
    generated_query = siem_templates.get(best_match or "failed_login", siem_templates["failed_login"])

    return {
        "siem_type": siem_type,
        "natural_language": nl_query,
        "generated_query": generated_query,
        "matched_category": best_match or "failed_login",
        "confidence": min(best_score / 15.0, 1.0) if best_score else 0.3,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
async def _async_sleep(seconds: float) -> None:
    """Wrapper so tests can patch sleep without importing asyncio."""
    import asyncio as _aio
    await _aio.sleep(seconds)
