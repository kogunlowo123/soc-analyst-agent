# SOC Analyst Agent — Testing Strategy

## Testing Pyramid

```
         /  E2E Tests  \         (~5% of tests, high cost, high confidence)
        / Integration   \        (~20% of tests, medium cost)
       /  Unit Tests     \       (~75% of tests, low cost, fast feedback)
      /__________________\
```

## Coverage Targets

| Component | Target | Rationale |
|-----------|--------|-----------|
| Agent core logic | 95% | Critical business logic — alert triage, IOC enrichment, MITRE mapping |
| API routes | 90% | All endpoints must have request/response validation tests |
| Auth service | 95% | Security-sensitive — JWT validation, RBAC enforcement |
| RAG pipeline | 85% | Retrieval quality directly impacts triage accuracy |
| Connectors | 80% | Mocked at boundary — verify request formatting and response parsing |
| MCP server | 85% | Tool dispatch must be reliable |
| Models/schemas | 90% | Validation logic must be thoroughly tested |
| Overall | 85% | Enforced via CI pipeline — builds fail below threshold |

## Test Frameworks

| Framework | Purpose |
|-----------|---------|
| pytest | Unit and integration testing |
| pytest-asyncio | Async function testing |
| pytest-cov | Coverage measurement |
| pytest-mock | Mock and spy injection |
| httpx | Async HTTP client for API testing |
| testcontainers | Integration testing with real databases |
| hypothesis | Property-based testing for schema validation |
| locust | Load testing |
| playwright | E2E dashboard testing |

## Unit Tests

### Location: `tests/unit/`

Unit tests are fast, isolated, and test individual functions without external dependencies.

### test_tools.py — Tool Function Tests

```python
import pytest
from src.agent.tools import AgentTools


@pytest.mark.asyncio
async def test_triage_alert_returns_verdict():
    """Triage should return a verdict with confidence score."""
    tools = AgentTools()
    result = await tools.triage_alert(
        alert_id="TEST-001",
        alert_data={"source": "splunk", "severity": "high", "rule_name": "Test Rule"}
    )
    assert "status" in result
    assert result["tool"] == "triage_alert"


@pytest.mark.asyncio
async def test_enrich_ioc_accepts_valid_indicator_types():
    """IOC enrichment should accept ipv4, domain, sha256, etc."""
    tools = AgentTools()
    for indicator_type in ["ipv4", "domain", "sha256", "md5", "url"]:
        result = await tools.enrich_ioc(
            indicator="test-indicator",
            indicator_type=indicator_type
        )
        assert result is not None


@pytest.mark.asyncio
async def test_query_siem_formats_query():
    """SIEM query should accept natural language and return formatted query."""
    tools = AgentTools()
    result = await tools.query_siem(
        query="show failed logins",
        index="auth-logs",
        time_range="1h"
    )
    assert result is not None
```

### test_prompts.py — Prompt Template Tests

```python
from src.agent.prompts import SYSTEM_PROMPT, RAG_CONTEXT_PROMPT, TOOL_SELECTION_PROMPT


def test_system_prompt_contains_soc_identity():
    """System prompt must establish SOC analyst identity."""
    assert "SOC" in SYSTEM_PROMPT
    assert "triage" in SYSTEM_PROMPT.lower() or "alert" in SYSTEM_PROMPT.lower()


def test_rag_context_prompt_has_placeholder():
    """RAG prompt must contain context placeholder."""
    assert "{context}" in RAG_CONTEXT_PROMPT


def test_tool_selection_prompt_has_placeholders():
    """Tool selection prompt must contain tools and request placeholders."""
    assert "{tools}" in TOOL_SELECTION_PROMPT
    assert "{request}" in TOOL_SELECTION_PROMPT
```

### test_schemas.py — Schema Validation Tests

```python
import pytest
from pydantic import ValidationError
from src.models.schemas import ChatRequest, AlertTriage, IOCEnrichment


def test_chat_request_requires_message():
    """ChatRequest must require a message field."""
    with pytest.raises(ValidationError):
        ChatRequest()


def test_chat_request_accepts_valid_input():
    """ChatRequest should accept valid message."""
    req = ChatRequest(message="Triage this alert")
    assert req.message == "Triage this alert"
    assert req.stream is False


def test_alert_triage_schema():
    """AlertTriage must contain verdict and confidence."""
    triage = AlertTriage(
        alert_id="TEST-001",
        verdict="true_positive",
        confidence=0.95,
        mitre_tactic="Execution",
        mitre_technique="T1059.001",
        recommended_action="escalate"
    )
    assert triage.confidence >= 0.0
    assert triage.confidence <= 1.0
```

## Integration Tests

### Location: `tests/integration/`

Integration tests verify that components work together correctly. They use testcontainers for real database instances.

### test_api.py — API Endpoint Integration Tests

```python
import pytest
from httpx import AsyncClient, ASGITransport
from src.api.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    """Health endpoint should return 200 with agent status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["agent"] == "soc-analyst-agent"


@pytest.mark.asyncio
async def test_alert_triage_endpoint_rejects_unauthenticated():
    """Alert triage endpoint should return 401 without auth token."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/alerts/triage",
            json={"alert_id": "TEST-001", "alert_data": {}}
        )
    assert response.status_code in [401, 403]


@pytest.mark.asyncio
async def test_openapi_docs_accessible():
    """OpenAPI documentation should be accessible."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/docs")
    assert response.status_code == 200
```

### test_siem_connector.py — SIEM Integration Tests

```python
import pytest
from unittest.mock import AsyncMock, patch
from src.connectors.domain_connectors import SplunkConnector


@pytest.mark.asyncio
async def test_splunk_connector_health_check():
    """Splunk connector should report health status."""
    connector = SplunkConnector(config={"host": "localhost", "port": 8089})
    health = await connector.health_check()
    assert "status" in health
    assert health["connector"] == "splunk"


@pytest.mark.asyncio
async def test_splunk_connector_formats_query():
    """Splunk connector should format SPL queries correctly."""
    connector = SplunkConnector(config={"host": "localhost", "port": 8089})
    with patch.object(connector, 'execute', new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = {"status": "success", "results": []}
        result = await connector.execute(
            operation="search",
            query="index=main | head 10"
        )
        assert result["status"] == "success"
```

## End-to-End Tests

### Location: `tests/e2e/`

E2E tests verify complete user workflows through the full stack.

### test_alert_workflow.py

```python
import pytest
from httpx import AsyncClient, ASGITransport
from src.api.main import app


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_full_alert_triage_workflow():
    """Test the complete alert triage workflow:
    1. Submit alert for triage
    2. Verify triage verdict
    3. Enrich extracted IOCs
    4. Correlate related events
    5. Generate investigation playbook
    6. Create incident report
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: Health check
        health = await client.get("/health")
        assert health.status_code == 200

        # Step 2: Verify docs are accessible
        docs = await client.get("/docs")
        assert docs.status_code == 200
```

## Load Tests

### Location: `tests/load/`

Load tests use Locust to verify performance under realistic conditions.

### locustfile.py

```python
from locust import HttpUser, task, between


class SOCAnalystUser(HttpUser):
    wait_time = between(1, 3)

    @task(5)
    def health_check(self):
        self.client.get("/health")

    @task(3)
    def triage_alert(self):
        self.client.post("/api/v1/alerts/triage", json={
            "alert_id": f"LOAD-TEST-{self.environment.runner.user_count}",
            "alert_data": {"source": "splunk", "severity": "medium"}
        }, headers={"Authorization": "Bearer test-token"})

    @task(2)
    def enrich_ioc(self):
        self.client.post("/api/v1/ioc/enrich", json={
            "indicator": "198.51.100.1",
            "indicator_type": "ipv4"
        }, headers={"Authorization": "Bearer test-token"})
```

### Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Alert triage latency (P50) | < 2 seconds | Time from alert submission to verdict |
| Alert triage latency (P95) | < 5 seconds | 95th percentile response time |
| Alert triage latency (P99) | < 10 seconds | 99th percentile response time |
| IOC enrichment latency | < 3 seconds | Dependent on threat intel API response |
| SIEM query latency | < 5 seconds | Dependent on SIEM query complexity |
| Throughput | > 100 alerts/minute | Sustained throughput under load |
| Error rate | < 0.1% | Server-side errors under normal load |
| Availability | > 99.9% | Monthly uptime target |

## Running Tests

```bash
# All tests
make test

# Unit tests only (fast, no external deps)
pytest tests/unit/ -v --cov=src --cov-report=term-missing

# Integration tests (requires docker-compose)
pytest tests/integration/ -v -m integration

# E2E tests
pytest tests/e2e/ -v -m e2e

# Load tests
locust -f tests/load/locustfile.py --host=http://localhost:8000

# Coverage report
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

## CI Integration

Tests run automatically in the CI pipeline:

1. **Lint**: ruff check (code style) + mypy (type checking)
2. **Unit Tests**: pytest tests/unit/ with coverage
3. **Integration Tests**: pytest tests/integration/ with testcontainers
4. **Security Scan**: bandit (SAST) + safety (dependency vulnerabilities)
5. **Coverage Gate**: Build fails if coverage drops below 85%
