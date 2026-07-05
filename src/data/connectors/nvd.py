"""NVD / CVE connector for the INDEXED data lane.

Queries the NIST NVD API 2.0 for CVE data, filtering by date range,
severity, and keyword.  Supports daily incremental sync by tracking
the ``lastModStartDate`` parameter.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
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
    wait=wait_exponential(multiplier=2, min=2, max=30),
    reraise=True,
)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_cvss_v31(metrics: dict[str, Any]) -> dict[str, Any]:
    """Extract CVSS v3.1 score and severity from NVD metrics."""
    v31_list = metrics.get("cvssMetricV31", [])
    if not v31_list:
        v30_list = metrics.get("cvssMetricV30", [])
        if v30_list:
            v31_list = v30_list

    if not v31_list:
        return {"score": 0.0, "severity": "UNKNOWN", "vector": ""}

    primary = v31_list[0]
    cvss = primary.get("cvssData", {})
    return {
        "score": cvss.get("baseScore", 0.0),
        "severity": cvss.get("baseSeverity", "UNKNOWN"),
        "vector": cvss.get("vectorString", ""),
    }


def _extract_affected_products(configurations: list[dict[str, Any]]) -> list[str]:
    """Extract CPE match strings as affected-product identifiers."""
    products: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe = match.get("criteria", "")
                    products.append(cpe)
    return products[:20]


class NVDConnector:
    """Fetches CVE data from the NIST NVD API 2.0.

    Args:
        api_key: NVD API key (optional, increases rate limit to 50 req/30s).
        days_back: Number of days to look back for initial sync.
        last_sync: ISO timestamp of the previous incremental sync.
        severity: Minimum CVSS severity filter (LOW, MEDIUM, HIGH, CRITICAL).
        keyword: Optional keyword filter for CVE descriptions.
    """

    def __init__(
        self,
        api_key: str = "",
        days_back: int = 30,
        last_sync: str | None = None,
        severity: str | None = None,
        keyword: str | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self._days_back = days_back
        self._last_sync = last_sync
        self._severity = severity
        self._keyword = keyword

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "NVDConnector":
        return cls(
            api_key=config.get("api_key", os.environ.get("NVD_API_KEY", "")),
            days_back=config.get("days_back", 30),
            last_sync=config.get("last_sync"),
            severity=config.get("severity"),
            keyword=config.get("keyword"),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_all(self) -> list[dict[str, Any]]:
        """Download CVEs and return one document per CVE."""
        cves = await self._fetch_cves()
        documents: list[dict[str, Any]] = []

        for cve_item in cves:
            cve = cve_item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "",
            )

            metrics = cve.get("metrics", {})
            cvss = _parse_cvss_v31(metrics)
            affected = _extract_affected_products(cve.get("configurations", []))
            references = [
                ref.get("url", "") for ref in cve.get("references", [])
            ][:10]
            weaknesses: list[str] = []
            for w in cve.get("weaknesses", []):
                for desc in w.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append(desc.get("value", ""))

            # Compose readable document
            sections = [
                f"# {cve_id}",
                "",
                f"**CVSS Score:** {cvss['score']} ({cvss['severity']})",
                f"**Vector:** {cvss['vector']}",
                f"**Published:** {cve.get('published', 'N/A')}",
                f"**Last Modified:** {cve.get('lastModified', 'N/A')}",
                "",
                "## Description",
                description_en,
            ]
            if affected:
                sections.extend([
                    "",
                    "## Affected Products",
                    "\n".join(f"- {p}" for p in affected),
                ])
            if weaknesses:
                sections.extend([
                    "",
                    "## Weaknesses",
                    "\n".join(f"- {w}" for w in weaknesses),
                ])
            if references:
                sections.extend([
                    "",
                    "## References",
                    "\n".join(f"- {r}" for r in references),
                ])

            text = "\n".join(sections)

            # Apply severity filter
            if self._severity:
                severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                min_idx = severity_order.index(self._severity.upper()) if self._severity.upper() in severity_order else 0
                cve_idx = severity_order.index(cvss["severity"]) if cvss["severity"] in severity_order else -1
                if cve_idx < min_idx:
                    continue

            documents.append(
                {
                    "text": text,
                    "metadata": {
                        "source": "nvd",
                        "cve_id": cve_id,
                        "cvss_score": cvss["score"],
                        "cvss_severity": cvss["severity"],
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                        "affected_products": affected,
                        "category": "vulnerability",
                    },
                }
            )

        logger.info("nvd_fetch_complete", cve_count=len(documents))
        return documents

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch_cves(self) -> list[dict[str, Any]]:
        """Paginate through the NVD API and collect CVE items."""
        now = datetime.now(timezone.utc)
        if self._last_sync:
            start_date = self._last_sync
        else:
            start_date = (now - timedelta(days=self._days_back)).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )
        end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        all_cves: list[dict[str, Any]] = []
        start_index = 0
        results_per_page = 200

        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        while True:
            params: dict[str, Any] = {
                "lastModStartDate": start_date,
                "lastModEndDate": end_date,
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
            if self._keyword:
                params["keywordSearch"] = self._keyword

            page = await self._fetch_page(params, headers)
            vulnerabilities = page.get("vulnerabilities", [])
            all_cves.extend(vulnerabilities)

            total_results = page.get("totalResults", 0)
            start_index += results_per_page

            logger.debug(
                "nvd_page_fetched",
                fetched=len(all_cves),
                total=total_results,
            )

            if start_index >= total_results:
                break

            # NVD rate limit: 5 req/30s without key, 50 req/30s with key
            import asyncio
            delay = 0.6 if self._api_key else 6.0
            await asyncio.sleep(delay)

        return all_cves

    @_RETRY
    async def _fetch_page(
        self,
        params: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=60) as c:
            resp = await c.get(_NVD_API_BASE, params=params, headers=headers)
            if resp.status_code == 403:
                logger.warning("nvd_rate_limited")
                import asyncio
                await asyncio.sleep(30)
                resp = await c.get(_NVD_API_BASE, params=params, headers=headers)
            resp.raise_for_status()
            return resp.json()
