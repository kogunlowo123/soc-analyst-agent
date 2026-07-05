"""Output validation sub-agent for the SOC Analyst Agent.

Validates orchestrator outputs before they reach the user:
  - Hallucinated IOC data (cross-references enrichment results)
  - MITRE ATT&CK technique ID validity
  - Dangerous action recommendations
  - Factual consistency between cited sources and claims
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    passed: bool
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    confidence_adjustment: float = 0.0  # negative = lower confidence


# ---------------------------------------------------------------------------
# Known-good MITRE technique IDs (subset; production would load full matrix)
# ---------------------------------------------------------------------------

_VALID_TECHNIQUE_PREFIXES = re.compile(r"^T\d{4}(\.\d{3})?$")

# Technique IDs known to exist in ATT&CK v15+
_KNOWN_TECHNIQUE_RANGE_MAX = 1699  # T0001..T1699 are plausible


# ---------------------------------------------------------------------------
# Dangerous recommendation patterns
# ---------------------------------------------------------------------------

_DANGEROUS_RECOMMENDATIONS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\b(run|execute)\s+(rm\s+-rf|format|del\s+/[sS])\b", re.I),
        "Recommends destructive file deletion command",
    ),
    (
        re.compile(r"\b(disable|turn\s+off)\s+(firewall|antivirus|edr|siem)\b", re.I),
        "Recommends disabling security controls",
    ),
    (
        re.compile(r"\b(share|post|publish)\s+(credentials?|passwords?|keys?)\b", re.I),
        "Recommends sharing credentials",
    ),
    (
        re.compile(r"\bignore\s+(the\s+)?alert\b", re.I),
        "Recommends ignoring a security alert without justification",
    ),
    (
        re.compile(r"\b(pay|transfer)\s+(the\s+)?ransom\b", re.I),
        "Recommends paying ransom",
    ),
    (
        re.compile(r"\bdo\s+not\s+(?:report|escalate|log)\b", re.I),
        "Recommends suppressing incident reporting",
    ),
]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class Validator:
    """Validate orchestrator outputs for correctness and safety."""

    async def validate(
        self,
        *,
        task_results: dict[str, Any],
        original_query: str,
        sources: list[dict[str, Any]],
    ) -> ValidationResult:
        """Run all validation checks against the accumulated task results.

        Returns a ValidationResult with pass/fail and specific issues.
        """
        result = ValidationResult(passed=True)

        # Flatten all text content from results for analysis
        all_text = self._flatten_text(task_results)

        # 1. Check for hallucinated IOC data
        self._check_hallucinated_iocs(all_text, task_results, result)
        result.checks_run.append("hallucinated_iocs")

        # 2. Validate MITRE technique IDs
        self._check_mitre_ids(all_text, result)
        result.checks_run.append("mitre_technique_ids")

        # 3. Check for dangerous recommendations
        self._check_dangerous_recommendations(all_text, result)
        result.checks_run.append("dangerous_recommendations")

        # 4. Check factual consistency
        self._check_factual_consistency(all_text, sources, result)
        result.checks_run.append("factual_consistency")

        # 5. Check for completeness
        self._check_completeness(task_results, result)
        result.checks_run.append("completeness")

        # Determine pass/fail based on issues
        if result.issues:
            result.passed = False

        logger.info(
            "validation_complete",
            passed=result.passed,
            issue_count=len(result.issues),
            warning_count=len(result.warnings),
            checks_run=result.checks_run,
        )

        return result

    # ------------------------------------------------------------------
    # Check: Hallucinated IOC data
    # ------------------------------------------------------------------

    def _check_hallucinated_iocs(
        self,
        text: str,
        task_results: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Cross-reference IOC data in output against enrichment results."""
        # Extract IOCs mentioned in the output
        output_ips = set(
            re.findall(
                r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
                text,
            )
        )
        output_hashes = set(
            m.group()
            for m in re.finditer(r"\b[a-fA-F0-9]{32,64}\b", text)
            if len(m.group()) in (32, 40, 64)
        )

        # Collect IOCs that appeared in enrichment results
        enriched_iocs: set[str] = set()
        for task_id, task_data in task_results.items():
            if isinstance(task_data, dict):
                enrichments = task_data.get("enrichments", {})
                for key in enrichments:
                    # Keys are formatted as "type:value"
                    parts = key.split(":", 1)
                    if len(parts) == 2:
                        enriched_iocs.add(parts[1])

        # Check for IPs in output that weren't in enrichment
        unenriched_ips = output_ips - enriched_iocs - {
            "127.0.0.1", "0.0.0.0", "255.255.255.255"
        }
        if unenriched_ips and enriched_iocs:
            result.warnings.append(
                f"Output references IP addresses not found in enrichment results: "
                f"{', '.join(list(unenriched_ips)[:5])}"
            )
            result.confidence_adjustment -= 0.10

        # Check for hashes in output that weren't enriched
        unenriched_hashes = output_hashes - enriched_iocs
        if unenriched_hashes and enriched_iocs:
            result.warnings.append(
                f"Output references hash values not in enrichment: "
                f"{', '.join(list(unenriched_hashes)[:3])}"
            )
            result.confidence_adjustment -= 0.10

        # Check for obviously fake hash patterns
        for h in output_hashes:
            if h == "0" * len(h) or h == "a" * len(h) or h == "f" * len(h):
                result.issues.append(
                    f"Likely fabricated hash detected: {h}"
                )
                result.confidence_adjustment -= 0.25

    # ------------------------------------------------------------------
    # Check: MITRE technique IDs
    # ------------------------------------------------------------------

    def _check_mitre_ids(self, text: str, result: ValidationResult) -> None:
        """Validate that referenced MITRE ATT&CK IDs are well-formed."""
        technique_refs = re.findall(r"\bT(\d{4})(?:\.(\d{3}))?\b", text)
        for main_id_str, sub_id_str in technique_refs:
            main_id = int(main_id_str)

            # Check range
            if main_id < 1 or main_id > _KNOWN_TECHNIQUE_RANGE_MAX:
                full_id = f"T{main_id_str}"
                if sub_id_str:
                    full_id += f".{sub_id_str}"
                result.issues.append(
                    f"Invalid MITRE ATT&CK technique ID: {full_id} "
                    f"(outside known range T0001-T{_KNOWN_TECHNIQUE_RANGE_MAX})"
                )
                result.confidence_adjustment -= 0.15

            # Check sub-technique range
            if sub_id_str:
                sub_id = int(sub_id_str)
                if sub_id < 1 or sub_id > 999:
                    result.warnings.append(
                        f"Unusual sub-technique number: T{main_id_str}.{sub_id_str}"
                    )

    # ------------------------------------------------------------------
    # Check: Dangerous recommendations
    # ------------------------------------------------------------------

    def _check_dangerous_recommendations(
        self, text: str, result: ValidationResult
    ) -> None:
        """Flag responses that suggest dangerous actions."""
        for pattern, reason in _DANGEROUS_RECOMMENDATIONS:
            if pattern.search(text):
                result.issues.append(f"Dangerous recommendation detected: {reason}")
                result.confidence_adjustment -= 0.30

    # ------------------------------------------------------------------
    # Check: Factual consistency
    # ------------------------------------------------------------------

    def _check_factual_consistency(
        self,
        text: str,
        sources: list[dict[str, Any]],
        result: ValidationResult,
    ) -> None:
        """Check that cited sources exist and claims reference valid indices."""
        # Look for citation patterns like [1], [2], etc.
        citations = set(int(m.group(1)) for m in re.finditer(r"\[(\d+)\]", text))

        if citations and sources:
            max_source_idx = len(sources)
            invalid_citations = {c for c in citations if c > max_source_idx or c < 1}
            if invalid_citations:
                result.warnings.append(
                    f"Citations reference non-existent sources: "
                    f"{sorted(invalid_citations)} (only {max_source_idx} sources available)"
                )
                result.confidence_adjustment -= 0.10

        # Check for contradictory severity assessments
        severity_mentions = re.findall(
            r"\b(critical|high|medium|low|informational)\s+(?:severity|risk|priority)\b",
            text,
            re.I,
        )
        if len(set(s.lower() for s in severity_mentions)) > 2:
            result.warnings.append(
                "Multiple conflicting severity levels mentioned in the same response"
            )
            result.confidence_adjustment -= 0.05

    # ------------------------------------------------------------------
    # Check: Completeness
    # ------------------------------------------------------------------

    def _check_completeness(
        self,
        task_results: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Ensure all planned tasks produced results."""
        failed_tasks: list[str] = []
        blocked_tasks: list[str] = []

        for task_id, task_data in task_results.items():
            if isinstance(task_data, dict):
                if task_data.get("blocked"):
                    blocked_tasks.append(task_id)
                elif task_data.get("success") is False:
                    failed_tasks.append(task_id)

        if failed_tasks:
            result.warnings.append(
                f"Some investigation tasks failed: {', '.join(failed_tasks)}"
            )
            result.confidence_adjustment -= 0.10

        if blocked_tasks:
            result.warnings.append(
                f"Some tasks were blocked by security guard: {', '.join(blocked_tasks)}"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flatten_text(task_results: dict[str, Any]) -> str:
        """Recursively extract all string values from task results."""
        parts: list[str] = []

        def _extract(obj: Any) -> None:
            if isinstance(obj, str):
                parts.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _extract(v)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    _extract(item)

        _extract(task_results)
        return " ".join(parts)
