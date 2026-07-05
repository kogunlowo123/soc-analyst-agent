"""Research sub-agent for the SOC Analyst Agent.

Synthesises findings from multiple sources:
  - RAG layer (internal knowledge base)
  - Threat intelligence APIs (IOC enrichment)
  - SIEM event correlation
  - MITRE ATT&CK mapping
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# MITRE ATT&CK reference (subset of commonly mapped techniques)
# ---------------------------------------------------------------------------

_MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1078.004": {"name": "Cloud Accounts", "tactic": "Defense Evasion"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "Exfiltration"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    "T1569": {"name": "System Services", "tactic": "Execution"},
    "T1569.002": {"name": "Service Execution", "tactic": "Execution"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1505": {"name": "Server Software Component", "tactic": "Persistence"},
    "T1505.003": {"name": "Web Shell", "tactic": "Persistence"},
}


# ---------------------------------------------------------------------------
# Research result
# ---------------------------------------------------------------------------


@dataclass
class ResearchResult:
    """Container for research findings from all sources."""

    findings: list[str] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    enrichments: dict[str, Any] = field(default_factory=dict)
    mitre_mappings: list[dict[str, str]] = field(default_factory=list)
    confidence: float = 0.0
    type: str = "research"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "findings": self.findings,
            "sources": self.sources,
            "enrichments": self.enrichments,
            "mitre_mappings": self.mitre_mappings,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Researcher
# ---------------------------------------------------------------------------


class Researcher:
    """Research sub-agent that gathers and synthesises security data."""

    async def investigate(
        self,
        *,
        query: str,
        prior_results: dict[str, Any] | None = None,
        enrichment_cache: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run a multi-source investigation for the given query.

        Pipeline:
        1. RAG retrieval for internal knowledge
        2. IOC enrichment via threat intelligence
        3. SIEM event correlation
        4. MITRE ATT&CK mapping
        5. Synthesis
        """
        start = time.time()
        result = ResearchResult()
        prior = prior_results or {}
        cache = enrichment_cache or {}

        # 1. RAG retrieval
        rag_findings = await self._query_rag(query)
        result.findings.extend(rag_findings.get("findings", []))
        result.sources.extend(rag_findings.get("sources", []))

        # 2. IOC enrichment
        iocs = self._extract_iocs(query)
        for ioc_type, values in iocs.items():
            for value in values:
                cache_key = f"{ioc_type}:{value}"
                if cache_key in cache:
                    result.enrichments[cache_key] = cache[cache_key]
                else:
                    enrichment = await self._enrich_ioc(value, ioc_type)
                    result.enrichments[cache_key] = enrichment
                    cache[cache_key] = enrichment

        # 3. SIEM correlation
        siem_results = await self._correlate_siem(query, prior)
        result.findings.extend(siem_results.get("findings", []))
        result.sources.extend(siem_results.get("sources", []))

        # 4. MITRE ATT&CK mapping
        mitre_mappings = self._map_to_mitre(query, result.findings)
        result.mitre_mappings = mitre_mappings

        # 5. Calculate confidence
        result.confidence = self._calculate_confidence(result)

        elapsed = (time.time() - start) * 1000
        logger.info(
            "research_complete",
            findings_count=len(result.findings),
            sources_count=len(result.sources),
            enrichments_count=len(result.enrichments),
            mitre_mappings_count=len(result.mitre_mappings),
            confidence=result.confidence,
            duration_ms=round(elapsed, 2),
        )

        return result.to_dict()

    # ------------------------------------------------------------------
    # RAG retrieval
    # ------------------------------------------------------------------

    async def _query_rag(self, query: str) -> dict[str, Any]:
        """Query the RAG pipeline for internal knowledge."""
        try:
            from src.rag.pipeline import RAGPipeline

            pipeline = RAGPipeline()
            results = await pipeline.retrieve(
                query=query,
                top_k=5,
                filters={"domain": "security_ai"},
            )
            findings = [
                r.get("content", "")[:500] for r in results if r.get("content")
            ]
            sources = [
                {
                    "title": r.get("title", "Internal KB"),
                    "source": r.get("source", "rag"),
                    "score": r.get("score", 0.0),
                }
                for r in results
            ]
            return {"findings": findings, "sources": sources}
        except Exception as exc:
            logger.warning("rag_retrieval_failed", error=str(exc))
            return {"findings": [], "sources": []}

    # ------------------------------------------------------------------
    # IOC enrichment
    # ------------------------------------------------------------------

    async def _enrich_ioc(
        self, indicator: str, indicator_type: str
    ) -> dict[str, Any]:
        """Enrich a single IOC via the tool layer."""
        try:
            from src.agent.tools import AgentTools

            result = await AgentTools.enrich_ioc(
                indicator=indicator, indicator_type=indicator_type
            )
            return result
        except Exception as exc:
            logger.warning(
                "ioc_enrichment_failed",
                indicator=indicator,
                type=indicator_type,
                error=str(exc),
            )
            return {
                "indicator": indicator,
                "type": indicator_type,
                "status": "enrichment_failed",
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # SIEM correlation
    # ------------------------------------------------------------------

    async def _correlate_siem(
        self, query: str, prior_results: dict[str, Any]
    ) -> dict[str, Any]:
        """Query SIEM for correlated events."""
        try:
            from src.agent.tools import AgentTools

            result = await AgentTools.correlate_events(
                query=query,
                time_range="24h",
                data_sources=["windows_security", "firewall", "proxy", "dns"],
            )
            return {
                "findings": [result.get("result", "")],
                "sources": [{"title": "SIEM Correlation", "source": "siem", "score": 0.8}],
            }
        except Exception as exc:
            logger.warning("siem_correlation_failed", error=str(exc))
            return {"findings": [], "sources": []}

    # ------------------------------------------------------------------
    # MITRE ATT&CK mapping
    # ------------------------------------------------------------------

    def _map_to_mitre(
        self, query: str, findings: list[str]
    ) -> list[dict[str, str]]:
        """Map query and findings to MITRE ATT&CK techniques."""
        combined_text = f"{query} {' '.join(findings)}".lower()
        mappings: list[dict[str, str]] = []
        seen: set[str] = set()

        # Keyword -> technique mapping
        keyword_map: dict[str, list[str]] = {
            "phishing": ["T1566"],
            "spearphishing": ["T1566.001", "T1566.002"],
            "powershell": ["T1059.001"],
            "cmd": ["T1059.003"],
            "brute force": ["T1110"],
            "password spray": ["T1110.003"],
            "credential dump": ["T1003"],
            "rdp": ["T1021.001"],
            "lateral movement": ["T1021"],
            "exfiltration": ["T1048"],
            "ransomware": ["T1486", "T1490"],
            "web shell": ["T1505.003"],
            "scheduled task": ["T1053.005"],
            "registry": ["T1547.001"],
            "valid account": ["T1078"],
            "obfuscat": ["T1027"],
            "masquerad": ["T1036"],
            "disable": ["T1562.001"],
            "exploit": ["T1190"],
            "vpn": ["T1133"],
            "c2": ["T1071.001"],
            "command and control": ["T1071"],
        }

        for keyword, technique_ids in keyword_map.items():
            if keyword in combined_text:
                for tid in technique_ids:
                    if tid not in seen and tid in _MITRE_TECHNIQUES:
                        seen.add(tid)
                        tech = _MITRE_TECHNIQUES[tid]
                        mappings.append(
                            {
                                "technique_id": tid,
                                "technique_name": tech["name"],
                                "tactic": tech["tactic"],
                            }
                        )

        # Also check for explicit technique ID references in text
        for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", query):
            tid = m.group()
            if tid not in seen and tid in _MITRE_TECHNIQUES:
                seen.add(tid)
                tech = _MITRE_TECHNIQUES[tid]
                mappings.append(
                    {
                        "technique_id": tid,
                        "technique_name": tech["name"],
                        "tactic": tech["tactic"],
                    }
                )

        return mappings

    # ------------------------------------------------------------------
    # Confidence calculation
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_confidence(result: ResearchResult) -> float:
        """Calculate overall confidence based on evidence quality."""
        score = 0.0
        max_score = 0.0

        # RAG sources found
        max_score += 0.30
        if result.sources:
            avg_score = sum(s.get("score", 0) for s in result.sources) / len(result.sources)
            score += 0.30 * min(avg_score, 1.0)

        # IOC enrichments succeeded
        max_score += 0.30
        if result.enrichments:
            success_count = sum(
                1
                for e in result.enrichments.values()
                if isinstance(e, dict) and e.get("status") != "enrichment_failed"
            )
            score += 0.30 * (success_count / max(len(result.enrichments), 1))

        # MITRE mappings found
        max_score += 0.20
        if result.mitre_mappings:
            score += min(0.20, 0.05 * len(result.mitre_mappings))

        # Number of distinct findings
        max_score += 0.20
        if result.findings:
            score += min(0.20, 0.04 * len(result.findings))

        return round(min(score / max(max_score, 0.01), 1.0), 2)

    # ------------------------------------------------------------------
    # IOC extraction (shared with planner but self-contained here)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_iocs(text: str) -> dict[str, list[str]]:
        iocs: dict[str, list[str]] = {}

        # IPv4
        ips = re.findall(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            text,
        )
        if ips:
            iocs["ip"] = list(set(ips))

        # Hashes
        hashes = [
            m.group()
            for m in re.finditer(r"\b[a-fA-F0-9]{32,64}\b", text)
            if len(m.group()) in (32, 40, 64)
        ]
        if hashes:
            iocs["hash"] = list(set(hashes))

        # Domains
        domains = [
            m.group()
            for m in re.finditer(
                r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
                text,
                re.I,
            )
            if not m.group().replace(".", "").isdigit()
        ]
        if domains:
            iocs["domain"] = list(set(domains))

        return iocs
