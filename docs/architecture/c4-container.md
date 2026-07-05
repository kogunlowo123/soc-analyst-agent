# C4 Container Diagram

## Overview

This diagram decomposes the SOC Analyst Agent system into its constituent containers -- the separately deployable units that make up the platform. Each container represents a process or data store that executes code or persists data, deployed as a Docker container within a Kubernetes cluster.

## Container Diagram

```mermaid
C4Container
    title SOC Analyst Agent - Container Diagram

    Person(analyst, "SOC Analyst", "Reviews triaged alerts and investigation reports via the dashboard")

    System_Boundary(soc_system, "SOC Analyst Agent System") {
        Container(dashboard, "Next.js Dashboard", "Next.js 14, React 18, TypeScript", "Real-time SOC dashboard showing alert queue, investigation timelines, MITRE ATT&CK heatmaps, and analyst workflow controls")
        Container(api, "FastAPI API Gateway", "Python 3.11, FastAPI 0.104, Uvicorn", "REST API serving alert ingestion endpoints, investigation queries, agent task orchestration, and WebSocket event streams on port 8000")
        Container(agent_engine, "Agent Engine", "Python 3.11, LangChain, OpenAI SDK", "Core AI reasoning engine that triages alerts, enriches IOCs, correlates events, maps to MITRE ATT&CK, and generates investigation playbooks")
        Container(rag_pipeline, "RAG Pipeline", "Python 3.11, LlamaIndex, sentence-transformers", "Retrieval-Augmented Generation pipeline that indexes security knowledge bases and retrieves contextual information for LLM-guided analysis")
        Container(mcp_server, "MCP Server", "Python 3.11, FastMCP", "Model Context Protocol server exposing SOC-specific tools: query_siem, enrich_ioc, correlate_events, generate_investigation, create_incident_report")
        Container(a2a_handler, "A2A Handler", "Python 3.11, httpx, JSON-RPC", "Agent-to-Agent protocol handler enabling communication with Threat Hunting, Incident Response, and Vulnerability Management agents")
        Container(celery_workers, "Celery Workers", "Python 3.11, Celery 5.3, Redis broker", "Distributed task workers executing long-running operations: bulk IOC enrichment, SIEM log queries, report generation, and scheduled correlation jobs")

        ContainerDb(postgres, "PostgreSQL 16", "PostgreSQL", "Persistent storage for alerts, investigations, playbooks, audit logs, user sessions, and agent configuration with row-level security")
        ContainerDb(redis, "Redis 7.2", "Redis", "In-memory cache for IOC enrichment results (TTL: 1h), session tokens, Celery task broker, rate limiter counters, and real-time pub/sub event bus")
        ContainerDb(opensearch, "OpenSearch 2.11", "OpenSearch", "Full-text search and vector store for security knowledge embeddings, alert indexing, investigation search, and RAG document retrieval")
    }

    System_Ext(siem, "SIEM Platforms", "Splunk, Elastic SIEM, Microsoft Sentinel")
    System_Ext(threat_intel, "Threat Intelligence", "VirusTotal, AbuseIPDB, MISP, Shodan")
    System_Ext(ticketing, "Ticketing Systems", "ServiceNow, Jira, PagerDuty")
    System_Ext(llm_provider, "LLM Provider", "OpenAI GPT-4o / Azure OpenAI / Anthropic Claude")

    Rel(analyst, dashboard, "Views alerts, triggers investigations", "HTTPS/443")
    Rel(dashboard, api, "Fetches data, submits actions", "HTTPS/443, REST + WebSocket")

    Rel(api, agent_engine, "Dispatches triage and analysis tasks", "Internal gRPC/50051")
    Rel(api, celery_workers, "Enqueues async tasks", "Redis/6379, AMQP")
    Rel(api, postgres, "Reads/writes alerts, investigations", "TCP/5432, SQLAlchemy")
    Rel(api, redis, "Caches responses, manages sessions", "TCP/6379")
    Rel(api, opensearch, "Searches alerts, retrieves documents", "HTTPS/9200")

    Rel(agent_engine, rag_pipeline, "Retrieves security context for analysis", "Internal HTTP/8001")
    Rel(agent_engine, mcp_server, "Invokes SOC tools via MCP protocol", "HTTP/8002, JSON-RPC")
    Rel(agent_engine, a2a_handler, "Delegates tasks to peer agents", "HTTP/8003, A2A Protocol")
    Rel(agent_engine, llm_provider, "Sends prompts, receives completions", "HTTPS/443, API Key")
    Rel(agent_engine, redis, "Caches enrichment results", "TCP/6379")

    Rel(rag_pipeline, opensearch, "Stores and retrieves embeddings", "HTTPS/9200")
    Rel(mcp_server, siem, "Executes SIEM queries", "HTTPS/8089,9200,443")
    Rel(mcp_server, threat_intel, "Enriches IOCs", "HTTPS/443")

    Rel(celery_workers, postgres, "Persists task results", "TCP/5432")
    Rel(celery_workers, redis, "Receives tasks from broker", "TCP/6379")
    Rel(celery_workers, siem, "Executes bulk log queries", "HTTPS/8089,9200")
    Rel(celery_workers, threat_intel, "Batch IOC enrichment", "HTTPS/443")
    Rel(celery_workers, ticketing, "Creates/updates tickets", "HTTPS/443")

    Rel(a2a_handler, soc_agent_peers, "Communicates with peer agents", "HTTPS/443, A2A")
```

## Container Descriptions

### Next.js Dashboard

- **Technology**: Next.js 14 with App Router, React 18, TypeScript, TailwindCSS, shadcn/ui
- **Port**: Served on port 3000 (internal), exposed via Ingress on port 443
- **Responsibilities**:
  - Real-time alert queue with severity filtering and priority sorting
  - Investigation timeline visualization with IOC enrichment results
  - MITRE ATT&CK heatmap showing tactic/technique coverage
  - Analyst workflow controls: acknowledge, escalate, close, add notes
  - WebSocket connection to API for live alert stream updates
  - Role-based views for SOC Analyst, SOC Manager, and IR Lead personas

### FastAPI API Gateway

- **Technology**: Python 3.11, FastAPI 0.104, Uvicorn with ASGI workers, Pydantic v2
- **Port**: 8000 (internal), exposed via Ingress on port 443
- **Responsibilities**:
  - RESTful endpoints for alert CRUD, investigation management, and agent control
  - WebSocket endpoint at `/ws/alerts` for real-time alert streaming
  - JWT-based authentication with OAuth2 authorization code flow
  - Request validation via Pydantic models with strict typing
  - Rate limiting via Redis-backed sliding window algorithm (100 req/min default)
  - OpenAPI documentation auto-generated at `/docs`
  - Health check at `/health` and readiness probe at `/ready`

### Agent Engine

- **Technology**: Python 3.11, LangChain 0.1, OpenAI SDK, custom orchestration
- **Port**: Internal gRPC on 50051
- **Responsibilities**:
  - Alert triage: classify severity (Critical/High/Medium/Low/Informational)
  - IOC extraction: parse IPs, domains, hashes, URLs, email addresses from alert payloads
  - IOC enrichment orchestration: fan-out queries to threat intelligence APIs
  - Event correlation: link related alerts by shared IOCs, timeframe, and affected assets
  - MITRE ATT&CK mapping: identify tactics (TA0001-TA0043) and techniques (T1001-T1657)
  - Severity reassessment: adjust priority based on enrichment and correlation results
  - Action recommendation: contain, escalate, monitor, or close with confidence scoring

### RAG Pipeline

- **Technology**: Python 3.11, LlamaIndex 0.10, sentence-transformers (all-MiniLM-L6-v2), OpenSearch
- **Port**: Internal HTTP on 8001
- **Responsibilities**:
  - Ingest security knowledge bases: MITRE ATT&CK, NIST SP 800-61, vendor advisories
  - Chunk documents using semantic splitting (512 tokens, 64 token overlap)
  - Generate embeddings via all-MiniLM-L6-v2 (384-dimensional vectors)
  - Store embeddings in OpenSearch k-NN index with HNSW algorithm
  - Retrieve relevant context using hybrid search (BM25 + vector similarity)
  - Rerank results using cross-encoder model (ms-marco-MiniLM-L-6-v2)
  - Inject top-k context (k=5) into LLM prompts for grounded analysis

### MCP Server

- **Technology**: Python 3.11, FastMCP framework, JSON-RPC 2.0
- **Port**: Internal HTTP on 8002
- **Responsibilities**:
  - Expose SOC-specific tools via Model Context Protocol
  - `query_siem`: Execute SPL/KQL/EQL queries against configured SIEM platforms
  - `enrich_ioc`: Query VirusTotal, AbuseIPDB, MISP, Shodan for IOC context
  - `correlate_events`: Find related alerts within configurable time windows
  - `generate_investigation`: Create step-by-step investigation playbooks
  - `create_incident_report`: Generate structured incident reports with IOC tables
  - Tool parameter validation and error handling with structured JSON responses

### A2A Handler

- **Technology**: Python 3.11, httpx async HTTP client, JSON-RPC 2.0
- **Port**: Internal HTTP on 8003
- **Responsibilities**:
  - Implement Google A2A (Agent-to-Agent) protocol for inter-agent communication
  - Publish agent card with capabilities, skills, and endpoint information
  - Route inbound task requests from peer agents to the Agent Engine
  - Dispatch outbound investigation requests to Threat Hunting Agent
  - Forward containment requests to Incident Response Agent
  - Share vulnerability context with Vulnerability Management Agent
  - Handle task lifecycle: submitted, working, completed, failed states

### Celery Workers

- **Technology**: Python 3.11, Celery 5.3.6, Redis as message broker
- **Port**: No exposed port (background workers)
- **Responsibilities**:
  - `bulk_enrich_iocs`: Process batches of IOCs with rate-limited API calls
  - `scheduled_siem_poll`: Poll SIEM platforms for new alerts on configurable intervals (default: 60s)
  - `generate_daily_report`: Compile 24-hour alert summary with metrics and trends
  - `correlation_sweep`: Run periodic correlation across alert backlog
  - `knowledge_base_sync`: Re-index updated security knowledge base documents
  - Retry with exponential backoff (max 3 retries, base delay 30s)
  - Dead letter queue for permanently failed tasks

### PostgreSQL 16

- **Port**: 5432
- **Schema highlights**:
  - `alerts`: Ingested alerts with SIEM source, raw payload, and triage status
  - `investigations`: Investigation sessions linking alerts, IOCs, and findings
  - `ioc_enrichments`: Cached enrichment results with TTL and source attribution
  - `playbooks`: Generated investigation playbooks with step-by-step procedures
  - `audit_logs`: Immutable audit trail of all agent and analyst actions
  - `agent_config`: Agent configuration, thresholds, and policy rules
- **Features**: Row-level security, connection pooling via PgBouncer, logical replication

### Redis 7.2

- **Port**: 6379
- **Usage**:
  - **Cache**: IOC enrichment results (TTL: 3600s), SIEM query results (TTL: 300s)
  - **Broker**: Celery task queue with priority lanes (critical, high, normal)
  - **Pub/Sub**: Real-time alert event bus for WebSocket fan-out
  - **Rate Limiter**: Sliding window counters for API and external service rate limiting
  - **Session Store**: JWT refresh token storage with automatic expiry
- **Configuration**: Persistence via AOF (appendfsync everysec), maxmemory-policy allkeys-lru

### OpenSearch 2.11

- **Port**: 9200
- **Indices**:
  - `alerts-*`: Time-series alert index with daily rollover (ILM: hot 7d, warm 30d, delete 90d)
  - `investigations-*`: Investigation documents with full-text search
  - `knowledge-embeddings`: k-NN vector index (384 dimensions, HNSW, ef_search: 256)
  - `ioc-intelligence`: IOC enrichment data for historical lookback
- **Configuration**: 3-node cluster, 1 primary + 1 replica per shard, ISM policies for lifecycle management
