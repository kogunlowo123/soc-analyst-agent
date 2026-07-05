"""Test configuration for SOC Analyst Agent."""

import pytest


@pytest.fixture
def agent_config():
    return {"name": "soc-analyst-agent", "category": "Security AI"}
