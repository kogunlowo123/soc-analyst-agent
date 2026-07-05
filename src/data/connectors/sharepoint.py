"""SharePoint connector for the INDEXED data lane.

Authenticates via Azure AD app registration (client-credentials flow),
lists sites and document libraries, fetches file content, and uses the
Microsoft Graph delta API for incremental sync.
"""

from __future__ import annotations

import io
import os
import re
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

_SUPPORTED_EXTENSIONS = {".docx", ".pdf", ".txt", ".md", ".html", ".htm", ".json", ".pptx", ".xlsx"}


class SharePointConnector:
    """Connects to SharePoint Online via Microsoft Graph.

    Args:
        tenant_id: Azure AD tenant ID.
        client_id: App registration client ID.
        client_secret: App registration client secret.
        site_ids: Specific site IDs to sync (empty = discover all).
        delta_link: Previous delta link for incremental sync.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        site_ids: list[str] | None = None,
        delta_link: str | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._site_ids = site_ids or []
        self._delta_link = delta_link
        self._access_token: str | None = None

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "SharePointConnector":
        return cls(
            tenant_id=config.get("tenant_id", os.environ.get("AZURE_TENANT_ID", "")),
            client_id=config.get("client_id", os.environ.get("AZURE_CLIENT_ID", "")),
            client_secret=config.get("client_secret", os.environ.get("AZURE_CLIENT_SECRET", "")),
            site_ids=config.get("site_ids", []),
            delta_link=config.get("delta_link"),
        )

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _ensure_token(self) -> str:
        """Obtain or reuse an access token from Azure AD."""
        if self._access_token:
            return self._access_token

        @_RETRY
        async def _get_token() -> str:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.post(
                    f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token",
                    data={
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "scope": "https://graph.microsoft.com/.default",
                        "grant_type": "client_credentials",
                    },
                )
                resp.raise_for_status()
                return resp.json()["access_token"]

        self._access_token = await _get_token()
        return self._access_token

    def _headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def list_sites(self) -> list[dict[str, Any]]:
        """Return all SharePoint sites the app has access to."""
        token = await self._ensure_token()

        @_RETRY
        async def _call() -> list[dict[str, Any]]:
            sites: list[dict[str, Any]] = []
            url: str | None = "https://graph.microsoft.com/v1.0/sites?search=*"
            async with httpx.AsyncClient(timeout=30) as c:
                while url:
                    resp = await c.get(url, headers=self._headers(token))
                    resp.raise_for_status()
                    data = resp.json()
                    sites.extend(
                        {
                            "id": s["id"],
                            "name": s.get("displayName"),
                            "web_url": s.get("webUrl"),
                        }
                        for s in data.get("value", [])
                    )
                    url = data.get("@odata.nextLink")
            return sites

        return await _call()

    async def fetch_all(self) -> list[dict[str, Any]]:
        """Fetch documents from configured sites and return for ingestion."""
        token = await self._ensure_token()
        site_ids = self._site_ids or [s["id"] for s in await self.list_sites()]
        documents: list[dict[str, Any]] = []

        for site_id in site_ids:
            drives = await self._list_drives(site_id, token)
            for drive in drives:
                files = await self._list_drive_files(drive["id"], token)
                for file_meta in files:
                    ext = os.path.splitext(file_meta.get("name", ""))[1].lower()
                    if ext not in _SUPPORTED_EXTENSIONS:
                        continue

                    content = await self._download_file(
                        drive["id"], file_meta["id"], token
                    )
                    if content is None:
                        continue

                    from ..ingestion import extract_text

                    text = extract_text(file_meta["name"], content)
                    if not text.strip():
                        continue

                    documents.append(
                        {
                            "text": text,
                            "metadata": {
                                "source": "sharepoint",
                                "site_id": site_id,
                                "drive_id": drive["id"],
                                "file_id": file_meta["id"],
                                "file_name": file_meta.get("name"),
                                "web_url": file_meta.get("webUrl"),
                                "last_modified": file_meta.get("lastModifiedDateTime"),
                                "size": file_meta.get("size"),
                                "category": "document_library",
                            },
                        }
                    )

        logger.info("sharepoint_fetch_complete", site_count=len(site_ids), doc_count=len(documents))
        return documents

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _list_drives(self, site_id: str, token: str) -> list[dict[str, Any]]:
        @_RETRY
        async def _call() -> list[dict[str, Any]]:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.get(
                    f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives",
                    headers=self._headers(token),
                )
                resp.raise_for_status()
                return [
                    {"id": d["id"], "name": d.get("name")}
                    for d in resp.json().get("value", [])
                ]

        try:
            return await _call()
        except Exception as exc:
            logger.warning("sharepoint_list_drives_failed", site=site_id, error=str(exc))
            return []

    async def _list_drive_files(
        self,
        drive_id: str,
        token: str,
    ) -> list[dict[str, Any]]:
        """List files in a drive, using delta API if a previous link exists."""

        @_RETRY
        async def _call() -> list[dict[str, Any]]:
            files: list[dict[str, Any]] = []
            if self._delta_link:
                url: str | None = self._delta_link
            else:
                url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root/delta"

            async with httpx.AsyncClient(timeout=60) as c:
                while url:
                    resp = await c.get(url, headers=self._headers(token))
                    resp.raise_for_status()
                    data = resp.json()

                    for item in data.get("value", []):
                        if item.get("file"):
                            files.append(
                                {
                                    "id": item["id"],
                                    "name": item.get("name"),
                                    "webUrl": item.get("webUrl"),
                                    "lastModifiedDateTime": item.get("lastModifiedDateTime"),
                                    "size": item.get("size"),
                                }
                            )

                    url = data.get("@odata.nextLink")
                    # Store the delta link for next incremental run
                    new_delta = data.get("@odata.deltaLink")
                    if new_delta:
                        self._delta_link = new_delta

            return files

        try:
            return await _call()
        except Exception as exc:
            logger.warning("sharepoint_list_files_failed", drive=drive_id, error=str(exc))
            return []

    async def _download_file(
        self,
        drive_id: str,
        item_id: str,
        token: str,
    ) -> bytes | None:
        @_RETRY
        async def _call() -> bytes:
            async with httpx.AsyncClient(timeout=60, follow_redirects=True) as c:
                resp = await c.get(
                    f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{item_id}/content",
                    headers=self._headers(token),
                )
                resp.raise_for_status()
                return resp.content

        try:
            return await _call()
        except Exception as exc:
            logger.warning("sharepoint_download_failed", item=item_id, error=str(exc))
            return None
