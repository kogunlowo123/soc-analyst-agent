"""MITRE ATT&CK connector for the INDEXED data lane.

Downloads the Enterprise ATT&CK STIX 2.1 bundle from the official
GitHub repository, parses techniques, tactics, mitigations, and groups,
and emits one document per technique for vector indexing.
Update frequency: monthly.
"""

from __future__ import annotations

import json
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
    wait=wait_exponential(multiplier=1, min=2, max=20),
    reraise=True,
)

_ENTERPRISE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _extract_external_id(obj: dict[str, Any]) -> str:
    """Pull the ATT&CK ID (e.g. T1059) from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _extract_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


class MitreAttackConnector:
    """Fetches and parses the MITRE ATT&CK Enterprise STIX bundle."""

    def __init__(self, stix_url: str | None = None) -> None:
        self._stix_url = stix_url or _ENTERPRISE_STIX_URL

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_all(self) -> list[dict[str, Any]]:
        """Download the STIX bundle and return one document per technique."""
        bundle = await self._download_bundle()
        objects = bundle.get("objects", [])

        # Build lookup maps for tactics and mitigations
        tactic_map = self._build_tactic_map(objects)
        mitigation_map = self._build_mitigation_map(objects)
        relationship_map = self._build_relationship_map(objects)
        group_map = self._build_group_map(objects)

        documents: list[dict[str, Any]] = []

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            technique_id = _extract_external_id(obj)
            name = obj.get("name", "")
            description = obj.get("description", "")
            platforms = obj.get("x_mitre_platforms", [])
            detection = obj.get("x_mitre_detection", "")

            # Resolve kill-chain phases to tactic names
            tactics = [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
            ]

            # Resolve mitigations via relationships
            obj_id = obj.get("id", "")
            mitigations: list[str] = []
            for rel_target in relationship_map.get(obj_id, []):
                mit = mitigation_map.get(rel_target)
                if mit:
                    mitigations.append(f"{mit['id']}: {mit['name']}")

            # Resolve groups
            groups: list[str] = []
            for rel_source in relationship_map.get(obj_id, []):
                grp = group_map.get(rel_source)
                if grp:
                    groups.append(f"{grp['id']}: {grp['name']}")

            # Compose the document text
            sections = [
                f"# {technique_id}: {name}",
                "",
                f"**Tactics:** {', '.join(tactics)}",
                f"**Platforms:** {', '.join(platforms)}",
                "",
                "## Description",
                description,
            ]
            if detection:
                sections.extend(["", "## Detection", detection])
            if mitigations:
                sections.extend(["", "## Mitigations", "\n".join(f"- {m}" for m in mitigations)])
            if groups:
                sections.extend(["", "## Threat Groups", "\n".join(f"- {g}" for g in groups)])

            text = "\n".join(sections)

            documents.append(
                {
                    "text": text,
                    "metadata": {
                        "source": "mitre_attack",
                        "technique_id": technique_id,
                        "name": name,
                        "tactics": tactics,
                        "platforms": platforms,
                        "url": _extract_url(obj),
                        "category": "threat_intelligence",
                    },
                }
            )

        logger.info("mitre_attack_fetch_complete", technique_count=len(documents))
        return documents

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _download_bundle(self) -> dict[str, Any]:
        @_RETRY
        async def _call() -> dict[str, Any]:
            async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
                resp = await c.get(self._stix_url)
                resp.raise_for_status()
                return resp.json()

        return await _call()

    @staticmethod
    def _build_tactic_map(objects: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
        """Map tactic STIX IDs to {id, name, short_name}."""
        result: dict[str, dict[str, str]] = {}
        for obj in objects:
            if obj.get("type") != "x-mitre-tactic":
                continue
            ext_id = _extract_external_id(obj)
            result[obj["id"]] = {
                "id": ext_id,
                "name": obj.get("name", ""),
                "short_name": obj.get("x_mitre_shortname", ""),
            }
        return result

    @staticmethod
    def _build_mitigation_map(objects: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        for obj in objects:
            if obj.get("type") != "course-of-action":
                continue
            ext_id = _extract_external_id(obj)
            result[obj["id"]] = {"id": ext_id, "name": obj.get("name", "")}
        return result

    @staticmethod
    def _build_group_map(objects: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            ext_id = _extract_external_id(obj)
            result[obj["id"]] = {"id": ext_id, "name": obj.get("name", "")}
        return result

    @staticmethod
    def _build_relationship_map(
        objects: list[dict[str, Any]],
    ) -> dict[str, list[str]]:
        """Map target_ref -> [source_ref] for 'mitigates' and 'uses' relationships."""
        result: dict[str, list[str]] = {}
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            rel_type = obj.get("relationship_type", "")
            if rel_type not in ("mitigates", "uses"):
                continue
            target = obj.get("target_ref", "")
            source = obj.get("source_ref", "")
            result.setdefault(target, []).append(source)
        return result
