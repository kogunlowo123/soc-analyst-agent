# Changelog

All notable changes to the SOC Analyst Agent will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2024-12-15

### Added

- Core alert triage engine with MITRE ATT&CK mapping
- IOC enrichment via VirusTotal, AbuseIPDB, and MISP integration
- Event correlation across Splunk, Elastic SIEM, and Microsoft Sentinel
- Natural language SIEM query translation (SPL, KQL, Lucene)
- Investigation playbook generation with executable SIEM queries
- Structured incident report generation
- RAG pipeline with OpenSearch vector store for security knowledge base
- MITRE ATT&CK knowledge base ingestion (all 14 tactics, 200+ techniques)
- MCP server with 6 domain-specific security tools
- A2A protocol for communication with Threat Hunting and Incident Response agents
- FastAPI backend with JWT, API key, and OAuth2 authentication
- RBAC authorization with 4 roles (analyst, lead, manager, admin)
- Next.js dashboard with real-time alert triage interface
- Comprehensive API with OpenAPI 3.1 specification
- Prometheus metrics and Grafana dashboards
- OpenTelemetry distributed tracing
- Structured logging with structlog
- Docker Compose development environment
- Kubernetes deployment manifests with NetworkPolicy and PDB
- Helm chart for production deployment
- Terraform infrastructure for AWS (EKS, RDS, ElastiCache, OpenSearch)
- GitHub Actions CI/CD pipelines (CI, CD, security scan)
- Unit tests (95% coverage on agent core)
- Integration tests with testcontainers
- Load tests with Locust
- Evaluation framework with golden test set (500 labeled alerts)
- Complete documentation: architecture, security, deployment, operations

### Security

- TLS 1.3 enforced for all external communication
- mTLS for agent-to-agent communication
- Secrets managed via environment variables (Vault/KMS in production)
- NetworkPolicy restricts pod-to-pod communication
- Non-root container execution with read-only filesystem
- Input validation on all API endpoints
- Rate limiting (100-1000 req/min by tier)
- Audit logging for all security-sensitive operations
