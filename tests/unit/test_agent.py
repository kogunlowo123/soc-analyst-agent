"""SOC Analyst Agent - Unit Tests."""

import pytest
from src.agent.tools import AgentTools


@pytest.mark.asyncio
async def test_triage_alert():
    """Test Triage a security alert and determine if it is a true positive."""
    tools = AgentTools()
    result = await tools.triage_alert(alert_id="test", alert_data="test")
    assert result is not None
    assert "status" in result or "tool" in result


@pytest.mark.asyncio
async def test_enrich_ioc():
    """Test Enrich an indicator of compromise with threat intelligence."""
    tools = AgentTools()
    result = await tools.enrich_ioc(indicator="test", indicator_type="test")
    assert result is not None
    assert "status" in result or "tool" in result


@pytest.mark.asyncio
async def test_correlate_events():
    """Test Correlate security events across multiple log sources."""
    tools = AgentTools()
    result = await tools.correlate_events(query="test", time_range="test")
    assert result is not None
    assert "status" in result or "tool" in result


@pytest.mark.asyncio
async def test_query_siem():
    """Test Execute a SIEM query (KQL, SPL, or Lucene)."""
    tools = AgentTools()
    result = await tools.query_siem(query="test", index="test")
    assert result is not None
    assert "status" in result or "tool" in result


@pytest.mark.asyncio
async def test_agent_initialization():
    """Test that the agent initializes correctly."""
    from src.agent.soc_analyst_agent_agent import SocAnalystAgentAgent
    agent = SocAnalystAgentAgent()
    assert agent.agent_id is not None
    assert agent._system_prompt is not None
    assert len(agent._tool_dispatch) > 0
