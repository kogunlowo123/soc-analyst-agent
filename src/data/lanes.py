"""Three-lane data architecture for the SOC Analyst Agent.

INDEXED  -- stable documents that pass through the RAG pipeline (chunked,
           embedded, vector-indexed).  Updated on a schedule.
LIVE     -- per-request data that is NEVER indexed.  Queried live at
           request time using the caller's permissions via Tool Layer.
STRUCTURED -- tabular data queried via NL2SQL against a read-only
             database replica.

``DataLaneRouter`` classifies an incoming query and dispatches it to the
correct lane.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class DataLane(str, Enum):
    """The three data lanes."""

    INDEXED = "indexed"
    LIVE = "live"
    STRUCTURED = "structured"


@dataclass(frozen=True)
class LaneResult:
    """Immutable result from a lane query."""

    lane: DataLane
    query: str
    results: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Classification keywords / patterns
# ---------------------------------------------------------------------------

_LIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bcurrent\b.*\balert", re.IGNORECASE),
    re.compile(r"\bopen\b.*\bincident", re.IGNORECASE),
    re.compile(r"\bactive\b.*\bthreat", re.IGNORECASE),
    re.compile(r"\breal[\s-]?time\b", re.IGNORECASE),
    re.compile(r"\bright now\b", re.IGNORECASE),
    re.compile(r"\blatest\b.*\bevent", re.IGNORECASE),
    re.compile(r"\bsiem\b", re.IGNORECASE),
    re.compile(r"\benrich\b.*\b(ip|domain|hash|url)\b", re.IGNORECASE),
    re.compile(r"\blookup\b", re.IGNORECASE),
    re.compile(r"\bquery\b.*\b(splunk|elastic|sentinel)\b", re.IGNORECASE),
]

_STRUCTURED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bhow many\b", re.IGNORECASE),
    re.compile(r"\bcount\b", re.IGNORECASE),
    re.compile(r"\baverage\b", re.IGNORECASE),
    re.compile(r"\btrend\b", re.IGNORECASE),
    re.compile(r"\bstatistic", re.IGNORECASE),
    re.compile(r"\bSLA\b"),
    re.compile(r"\bmetric", re.IGNORECASE),
    re.compile(r"\bpercentage\b", re.IGNORECASE),
    re.compile(r"\btop\s+\d+", re.IGNORECASE),
    re.compile(r"\bcompare\b.*\b(month|week|quarter|year)", re.IGNORECASE),
    re.compile(r"\bgroup\s+by\b", re.IGNORECASE),
]


def _classify(query: str) -> DataLane:
    """Heuristic classifier that routes a query to a lane."""
    live_score = sum(1 for p in _LIVE_PATTERNS if p.search(query))
    structured_score = sum(1 for p in _STRUCTURED_PATTERNS if p.search(query))

    if live_score > structured_score:
        return DataLane.LIVE
    if structured_score > live_score:
        return DataLane.STRUCTURED
    return DataLane.INDEXED


# ---------------------------------------------------------------------------
# DataLaneRouter
# ---------------------------------------------------------------------------

class DataLaneRouter:
    """Classify a query and dispatch it to the appropriate data lane.

    Dependencies are injected for each lane backend:
      * ``rag_pipeline``   -- handles INDEXED queries (vector search)
      * ``tool_registry``  -- handles LIVE queries (tool execution)
      * ``sql_executor``   -- handles STRUCTURED queries (NL2SQL)
    """

    def __init__(
        self,
        rag_pipeline: Any = None,
        tool_registry: Any = None,
        sql_executor: Any = None,
    ) -> None:
        self._rag = rag_pipeline
        self._tools = tool_registry
        self._sql = sql_executor

    def classify(self, query: str) -> DataLane:
        """Return the lane a query would be routed to."""
        return _classify(query)

    async def route(
        self,
        query: str,
        user_context: dict[str, Any] | None = None,
    ) -> LaneResult:
        """Classify and execute the query via the appropriate lane."""
        lane = _classify(query)
        logger.info("lane_routed", lane=lane.value, query=query[:120])

        if lane == DataLane.LIVE:
            return await self._handle_live(query, user_context or {})
        if lane == DataLane.STRUCTURED:
            return await self._handle_structured(query, user_context or {})
        return await self._handle_indexed(query, user_context or {})

    # ------------------------------------------------------------------
    # INDEXED lane
    # ------------------------------------------------------------------

    async def _handle_indexed(
        self,
        query: str,
        user_context: dict[str, Any],
    ) -> LaneResult:
        """Vector-search over the pre-indexed knowledge base."""
        if self._rag is None:
            logger.warning("indexed_lane_no_rag")
            return LaneResult(lane=DataLane.INDEXED, query=query, results=[])

        try:
            results = await self._rag.retrieve(query, top_k=5)
            return LaneResult(
                lane=DataLane.INDEXED,
                query=query,
                results=results,
                metadata={"source": "vector_index"},
            )
        except Exception as exc:
            logger.error("indexed_lane_failed", error=str(exc))
            return LaneResult(lane=DataLane.INDEXED, query=query, results=[], metadata={"error": str(exc)})

    # ------------------------------------------------------------------
    # LIVE lane
    # ------------------------------------------------------------------

    async def _handle_live(
        self,
        query: str,
        user_context: dict[str, Any],
    ) -> LaneResult:
        """Query live data via the Tool Layer using caller's permissions."""
        if self._tools is None:
            logger.warning("live_lane_no_tools")
            return LaneResult(lane=DataLane.LIVE, query=query, results=[])

        # Determine which tool to invoke based on query content
        tool_name = self._select_live_tool(query)
        try:
            result = await self._tools.execute(
                tool_name,
                {"query": query},
                user_context,
            )
            return LaneResult(
                lane=DataLane.LIVE,
                query=query,
                results=[result.data] if result.success else [],
                metadata={"tool": tool_name, "success": result.success},
            )
        except Exception as exc:
            logger.error("live_lane_failed", error=str(exc))
            return LaneResult(lane=DataLane.LIVE, query=query, results=[], metadata={"error": str(exc)})

    @staticmethod
    def _select_live_tool(query: str) -> str:
        """Simple heuristic to pick the right live tool."""
        q = query.lower()
        if any(kw in q for kw in ("splunk", "spl")):
            return "query_splunk"
        if any(kw in q for kw in ("elastic", "elasticsearch")):
            return "query_elastic"
        if any(kw in q for kw in ("sentinel", "azure")):
            return "query_sentinel"
        if any(kw in q for kw in ("enrich", "reputation", "virustotal")):
            return "enrich_ip"
        if any(kw in q for kw in ("incident", "alert")):
            return "query_splunk"
        return "query_splunk"

    # ------------------------------------------------------------------
    # STRUCTURED lane
    # ------------------------------------------------------------------

    async def _handle_structured(
        self,
        query: str,
        user_context: dict[str, Any],
    ) -> LaneResult:
        """Translate natural language to SQL and execute against replica."""
        if self._sql is None:
            logger.warning("structured_lane_no_sql")
            return LaneResult(lane=DataLane.STRUCTURED, query=query, results=[])

        try:
            sql_query = await self._nl_to_sql(query)
            rows = await self._sql.execute(sql_query, user_context)
            return LaneResult(
                lane=DataLane.STRUCTURED,
                query=query,
                results=rows,
                metadata={"generated_sql": sql_query},
            )
        except Exception as exc:
            logger.error("structured_lane_failed", error=str(exc))
            return LaneResult(lane=DataLane.STRUCTURED, query=query, results=[], metadata={"error": str(exc)})

    @staticmethod
    async def _nl_to_sql(query: str) -> str:
        """Simple template-based NL-to-SQL for common SOC metrics.

        For production, route through the LLM layer with a SQL-generation
        system prompt and schema context.
        """
        q = query.lower()

        if "how many" in q and "incident" in q:
            return "SELECT COUNT(*) AS total_incidents FROM incidents WHERE created_at >= NOW() - INTERVAL '30 days'"
        if "average" in q and ("time" in q or "resolution" in q):
            return (
                "SELECT AVG(EXTRACT(EPOCH FROM resolved_at - created_at) / 3600) AS avg_resolution_hours "
                "FROM incidents WHERE resolved_at IS NOT NULL AND created_at >= NOW() - INTERVAL '30 days'"
            )
        if "sla" in q:
            return (
                "SELECT severity, "
                "COUNT(*) FILTER (WHERE resolved_within_sla) * 100.0 / COUNT(*) AS sla_compliance_pct "
                "FROM incidents WHERE created_at >= NOW() - INTERVAL '30 days' GROUP BY severity"
            )
        if "top" in q and "alert" in q:
            return (
                "SELECT alert_name, COUNT(*) AS occurrence_count "
                "FROM alerts WHERE created_at >= NOW() - INTERVAL '7 days' "
                "GROUP BY alert_name ORDER BY occurrence_count DESC LIMIT 10"
            )
        if "trend" in q:
            return (
                "SELECT DATE_TRUNC('day', created_at) AS day, COUNT(*) AS daily_count "
                "FROM incidents WHERE created_at >= NOW() - INTERVAL '30 days' "
                "GROUP BY day ORDER BY day"
            )

        # Fall back: pass through so the LLM can handle it
        return f"-- NL2SQL could not translate: {query}"
