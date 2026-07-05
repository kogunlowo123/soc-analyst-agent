"""Confluence connector for the INDEXED data lane.

Authenticates via API token, lists spaces, fetches page content
(with attachments), and supports incremental sync based on the
``lastModified`` timestamp of each page.
"""

from __future__ import annotations

import os
import re
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
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)


def _strip_confluence_markup(storage_body: str) -> str:
    """Convert Confluence storage-format XHTML to plain text."""
    text = re.sub(r"<ac:[^>]*/>", " ", storage_body)
    text = re.sub(r"<ac:[^>]*>.*?</ac:[^>]*>", " ", text, flags=re.DOTALL)
    text = re.sub(r"<ri:[^>]*/>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


class ConfluenceConnector:
    """Connects to Atlassian Confluence Cloud or Data Center.

    Args:
        base_url: Confluence base URL (e.g. https://wiki.corp.local).
        email: User e-mail (Cloud) or username (DC).
        api_token: API token or personal-access token.
        spaces: List of space keys to sync (empty = all).
        last_sync: ISO timestamp of the previous sync for incremental.
    """

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        spaces: list[str] | None = None,
        last_sync: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._api_token = api_token
        self._spaces = spaces or []
        self._last_sync = last_sync

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "ConfluenceConnector":
        return cls(
            base_url=config.get("base_url", os.environ.get("CONFLUENCE_BASE_URL", "")),
            email=config.get("email", os.environ.get("CONFLUENCE_EMAIL", "")),
            api_token=config.get("api_token", os.environ.get("CONFLUENCE_API_TOKEN", "")),
            spaces=config.get("spaces", []),
            last_sync=config.get("last_sync"),
        )

    def _auth(self) -> tuple[str, str]:
        return (self._email, self._api_token)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def list_spaces(self) -> list[dict[str, Any]]:
        """Return all Confluence spaces accessible to the service account."""

        @_RETRY
        async def _call() -> list[dict[str, Any]]:
            spaces: list[dict[str, Any]] = []
            start = 0
            limit = 50
            async with httpx.AsyncClient(auth=self._auth(), timeout=30) as c:
                while True:
                    resp = await c.get(
                        f"{self._base_url}/rest/api/space",
                        params={"start": start, "limit": limit},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    results = data.get("results", [])
                    spaces.extend(
                        {"key": s["key"], "name": s["name"], "type": s.get("type")}
                        for s in results
                    )
                    if data.get("size", 0) < limit:
                        break
                    start += limit
            return spaces

        return await _call()

    async def fetch_all(self) -> list[dict[str, Any]]:
        """Fetch all pages (optionally incremental) and return documents.

        Each document is a dict with ``text`` and ``metadata``.
        """
        spaces_to_sync = self._spaces or [s["key"] for s in await self.list_spaces()]
        documents: list[dict[str, Any]] = []

        for space_key in spaces_to_sync:
            pages = await self._fetch_space_pages(space_key)
            for page in pages:
                text = _strip_confluence_markup(page.get("body", ""))
                if not text:
                    continue
                documents.append(
                    {
                        "text": text,
                        "metadata": {
                            "source": "confluence",
                            "space": space_key,
                            "page_id": page.get("id"),
                            "title": page.get("title"),
                            "url": f"{self._base_url}/wiki/spaces/{space_key}/pages/{page.get('id')}",
                            "last_modified": page.get("last_modified"),
                            "category": "knowledge_base",
                        },
                    }
                )

        logger.info("confluence_fetch_complete", space_count=len(spaces_to_sync), doc_count=len(documents))
        return documents

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch_space_pages(self, space_key: str) -> list[dict[str, Any]]:
        """Fetch pages from a single space, with optional incremental filter."""

        @_RETRY
        async def _call() -> list[dict[str, Any]]:
            pages: list[dict[str, Any]] = []
            start = 0
            limit = 25
            async with httpx.AsyncClient(auth=self._auth(), timeout=60) as c:
                while True:
                    params: dict[str, Any] = {
                        "spaceKey": space_key,
                        "expand": "body.storage,version",
                        "start": start,
                        "limit": limit,
                    }
                    if self._last_sync:
                        params["lastModified"] = self._last_sync

                    resp = await c.get(
                        f"{self._base_url}/rest/api/content",
                        params=params,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    results = data.get("results", [])

                    for page in results:
                        body = page.get("body", {}).get("storage", {}).get("value", "")
                        version = page.get("version", {})
                        pages.append(
                            {
                                "id": page.get("id"),
                                "title": page.get("title"),
                                "body": body,
                                "last_modified": version.get("when"),
                            }
                        )

                    if data.get("size", 0) < limit:
                        break
                    start += limit

            return pages

        return await _call()
