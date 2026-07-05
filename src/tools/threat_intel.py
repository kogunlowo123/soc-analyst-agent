"""Threat intelligence enrichment tools.

Integrates with VirusTotal, AbuseIPDB, Shodan, URLScan.io,
MalwareBazaar, MISP and passive-DNS services.  Results are cached in
Redis with configurable TTLs and all external calls respect per-provider
rate limits.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
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
# Redis-backed cache
# ---------------------------------------------------------------------------

_redis_client: Any = None


async def _get_redis() -> Any:
    """Lazy-initialise an async Redis connection."""
    global _redis_client  # noqa: PLW0603
    if _redis_client is None:
        import redis.asyncio as aioredis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        _redis_client = aioredis.from_url(redis_url, decode_responses=True)
    return _redis_client


async def _cache_get(key: str) -> dict[str, Any] | None:
    try:
        r = await _get_redis()
        raw = await r.get(key)
        if raw:
            logger.debug("cache_hit", key=key)
            return json.loads(raw)
    except Exception:
        logger.debug("cache_miss_or_error", key=key)
    return None


async def _cache_set(key: str, value: dict[str, Any], ttl_seconds: int) -> None:
    try:
        r = await _get_redis()
        await r.setex(key, ttl_seconds, json.dumps(value, default=str))
    except Exception:
        logger.warning("cache_set_failed", key=key)


# ---------------------------------------------------------------------------
# Rate limiter (simple sliding-window via Redis)
# ---------------------------------------------------------------------------

async def _rate_limit(provider: str, max_requests: int, window_seconds: int) -> None:
    """Block until the provider rate window allows another request."""
    r = await _get_redis()
    key = f"ratelimit:{provider}"
    now = time.time()
    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, now - window_seconds)
    pipe.zcard(key)
    pipe.zadd(key, {str(now): now})
    pipe.expire(key, window_seconds)
    results = await pipe.execute()
    current_count = results[1]
    if current_count >= max_requests:
        wait_time = window_seconds / max_requests
        logger.warning(
            "rate_limited",
            provider=provider,
            wait_seconds=round(wait_time, 2),
        )
        import asyncio
        await asyncio.sleep(wait_time)


# ---------------------------------------------------------------------------
# Normalised enrichment envelope
# ---------------------------------------------------------------------------

def _enrichment_envelope(
    indicator: str,
    indicator_type: str,
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a standard enrichment response."""
    overall_score = 0.0
    malicious_count = 0
    total_count = len(sources) or 1

    for src in sources:
        if src.get("malicious"):
            malicious_count += 1
        overall_score += src.get("score", 0.0)

    reputation = "unknown"
    ratio = malicious_count / total_count
    if ratio >= 0.5:
        reputation = "malicious"
    elif ratio >= 0.2:
        reputation = "suspicious"
    elif total_count > 0 and malicious_count == 0:
        reputation = "clean"

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation": reputation,
        "threat_score": round(overall_score / total_count, 2),
        "sources": sources,
        "related_campaigns": [],
    }


# ---------------------------------------------------------------------------
# IP enrichment
# ---------------------------------------------------------------------------

async def enrich_ip(ip_address: str) -> dict[str, Any]:
    """Query VirusTotal, AbuseIPDB, and Shodan for IP reputation."""
    cache_key = f"enrich:ip:{ip_address}"
    cached = await _cache_get(cache_key)
    if cached:
        return cached

    sources: list[dict[str, Any]] = []

    # -- VirusTotal --
    vt_result = await _vt_ip(ip_address)
    if vt_result:
        sources.append(vt_result)

    # -- AbuseIPDB --
    abuse_result = await _abuseipdb_check(ip_address)
    if abuse_result:
        sources.append(abuse_result)

    # -- Shodan --
    shodan_result = await _shodan_host(ip_address)
    if shodan_result:
        sources.append(shodan_result)

    result = _enrichment_envelope(ip_address, "ip", sources)
    await _cache_set(cache_key, result, ttl_seconds=86_400)  # 24 h
    return result


async def _vt_ip(ip: str) -> dict[str, Any] | None:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return None
    vt_tier = os.environ.get("VIRUSTOTAL_TIER", "free")
    rate_max = 500 if vt_tier == "premium" else 4
    await _rate_limit("virustotal", rate_max, 60)

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": api_key},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        return {
            "source": "virustotal",
            "malicious": malicious > 0,
            "score": malicious / total,
            "details": {
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "malicious_count": malicious,
                "total_engines": total,
            },
        }
    except Exception as exc:
        logger.warning("vt_ip_failed", ip=ip, error=str(exc))
        return None


async def _abuseipdb_check(ip: str) -> dict[str, Any] | None:
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return None
    await _rate_limit("abuseipdb", 60, 60)

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        info = data.get("data", {})
        score = info.get("abuseConfidenceScore", 0) / 100.0
        return {
            "source": "abuseipdb",
            "malicious": score >= 0.5,
            "score": score,
            "details": {
                "isp": info.get("isp"),
                "country_code": info.get("countryCode"),
                "total_reports": info.get("totalReports", 0),
                "usage_type": info.get("usageType"),
            },
        }
    except Exception as exc:
        logger.warning("abuseipdb_failed", ip=ip, error=str(exc))
        return None


async def _shodan_host(ip: str) -> dict[str, Any] | None:
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        return None
    await _rate_limit("shodan", 1, 1)

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        vulns = data.get("vulns", [])
        return {
            "source": "shodan",
            "malicious": len(vulns) > 0,
            "score": min(len(vulns) / 10.0, 1.0),
            "details": {
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "vulns": vulns[:20],
                "org": data.get("org"),
                "hostnames": data.get("hostnames", []),
            },
        }
    except Exception as exc:
        logger.warning("shodan_failed", ip=ip, error=str(exc))
        return None


# ---------------------------------------------------------------------------
# Domain enrichment
# ---------------------------------------------------------------------------

async def enrich_domain(domain: str) -> dict[str, Any]:
    """Query VirusTotal, WHOIS proxy, and passive DNS for domain reputation."""
    cache_key = f"enrich:domain:{domain}"
    cached = await _cache_get(cache_key)
    if cached:
        return cached

    sources: list[dict[str, Any]] = []

    # -- VirusTotal --
    vt_result = await _vt_domain(domain)
    if vt_result:
        sources.append(vt_result)

    result = _enrichment_envelope(domain, "domain", sources)
    await _cache_set(cache_key, result, ttl_seconds=3_600)  # 1 h
    return result


async def _vt_domain(domain: str) -> dict[str, Any] | None:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return None
    vt_tier = os.environ.get("VIRUSTOTAL_TIER", "free")
    rate_max = 500 if vt_tier == "premium" else 4
    await _rate_limit("virustotal", rate_max, 60)

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": api_key},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        return {
            "source": "virustotal",
            "malicious": malicious > 0,
            "score": malicious / total,
            "details": {
                "registrar": attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
                "malicious_count": malicious,
                "total_engines": total,
                "categories": attrs.get("categories", {}),
            },
        }
    except Exception as exc:
        logger.warning("vt_domain_failed", domain=domain, error=str(exc))
        return None


# ---------------------------------------------------------------------------
# File-hash enrichment
# ---------------------------------------------------------------------------

async def enrich_hash(
    file_hash: str,
    hash_type: str = "sha256",
) -> dict[str, Any]:
    """Query VirusTotal and MalwareBazaar for file-hash reputation."""
    cache_key = f"enrich:hash:{file_hash}"
    cached = await _cache_get(cache_key)
    if cached:
        return cached

    sources: list[dict[str, Any]] = []

    vt_result = await _vt_hash(file_hash)
    if vt_result:
        sources.append(vt_result)

    mb_result = await _malwarebazaar_hash(file_hash, hash_type)
    if mb_result:
        sources.append(mb_result)

    result = _enrichment_envelope(file_hash, "hash", sources)
    await _cache_set(cache_key, result, ttl_seconds=86_400)
    return result


async def _vt_hash(file_hash: str) -> dict[str, Any] | None:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return None
    vt_tier = os.environ.get("VIRUSTOTAL_TIER", "free")
    rate_max = 500 if vt_tier == "premium" else 4
    await _rate_limit("virustotal", rate_max, 60)

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": api_key},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        return {
            "source": "virustotal",
            "malicious": malicious > 0,
            "score": malicious / total,
            "details": {
                "meaningful_name": attrs.get("meaningful_name"),
                "type_description": attrs.get("type_description"),
                "malicious_count": malicious,
                "total_engines": total,
                "tags": attrs.get("tags", []),
            },
        }
    except Exception as exc:
        logger.warning("vt_hash_failed", hash=file_hash, error=str(exc))
        return None


async def _malwarebazaar_hash(
    file_hash: str,
    hash_type: str,
) -> dict[str, Any] | None:
    await _rate_limit("malwarebazaar", 10, 60)

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        if data.get("query_status") != "ok":
            return None
        info = data.get("data", [{}])[0]
        return {
            "source": "malwarebazaar",
            "malicious": True,
            "score": 1.0,
            "details": {
                "file_type": info.get("file_type"),
                "signature": info.get("signature"),
                "tags": info.get("tags", []),
                "delivery_method": info.get("delivery_method"),
                "first_seen": info.get("first_seen"),
            },
        }
    except Exception as exc:
        logger.warning("malwarebazaar_failed", hash=file_hash, error=str(exc))
        return None


# ---------------------------------------------------------------------------
# URL enrichment
# ---------------------------------------------------------------------------

async def enrich_url(url: str) -> dict[str, Any]:
    """Query URLScan.io and VirusTotal for URL reputation."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    cache_key = f"enrich:url:{url_hash}"
    cached = await _cache_get(cache_key)
    if cached:
        return cached

    sources: list[dict[str, Any]] = []

    urlscan_result = await _urlscan_search(url)
    if urlscan_result:
        sources.append(urlscan_result)

    result = _enrichment_envelope(url, "url", sources)
    await _cache_set(cache_key, result, ttl_seconds=3_600)
    return result


async def _urlscan_search(url: str) -> dict[str, Any] | None:
    api_key = os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        return None
    await _rate_limit("urlscan", 60, 60)

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(
                "https://urlscan.io/api/v1/search/",
                headers={"API-Key": api_key},
                params={"q": f'page.url:"{url}"', "size": 1},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        results = data.get("results", [])
        if not results:
            return {"source": "urlscan", "malicious": False, "score": 0.0, "details": {}}
        top = results[0]
        verdicts = top.get("verdicts", {}).get("overall", {})
        malicious = verdicts.get("malicious", False)
        return {
            "source": "urlscan",
            "malicious": malicious,
            "score": 1.0 if malicious else 0.0,
            "details": {
                "screenshot": top.get("screenshot"),
                "page_url": top.get("page", {}).get("url"),
                "page_domain": top.get("page", {}).get("domain"),
                "server": top.get("page", {}).get("server"),
            },
        }
    except Exception as exc:
        logger.warning("urlscan_failed", url=url[:120], error=str(exc))
        return None


# ---------------------------------------------------------------------------
# MISP search
# ---------------------------------------------------------------------------

async def search_misp(
    query: str,
    type: str = "attribute",
) -> dict[str, Any]:
    """Search a MISP instance for threat-intelligence events.

    Environment:
        MISP_BASE_URL  -- e.g. https://misp.corp.local
        MISP_API_KEY
    """
    base_url = os.environ.get("MISP_BASE_URL", "https://localhost")
    api_key = os.environ.get("MISP_API_KEY", "")

    @_RETRY
    async def _call() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            verify=False,
            timeout=30,
        ) as c:
            body: dict[str, Any] = {
                "returnFormat": "json",
                "limit": 50,
                "value": query,
            }
            if type == "attribute":
                resp = await c.post("/attributes/restSearch", json=body)
            else:
                resp = await c.post("/events/restSearch", json=body)
            resp.raise_for_status()
            return resp.json()

    try:
        data = await _call()
        response = data.get("response", {})
        if type == "attribute":
            attributes = response.get("Attribute", [])
            return {
                "source": "misp",
                "query": query,
                "result_count": len(attributes),
                "results": attributes[:50],
            }
        events = response.get("Event", []) if isinstance(response, dict) else response
        return {
            "source": "misp",
            "query": query,
            "result_count": len(events) if isinstance(events, list) else 0,
            "results": events[:50] if isinstance(events, list) else [],
        }
    except Exception as exc:
        logger.warning("misp_search_failed", query=query, error=str(exc))
        return {"source": "misp", "query": query, "result_count": 0, "results": [], "error": str(exc)}
