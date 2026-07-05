# Compatibility Matrix

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## Component Version Compatibility

| Component | Minimum Version | Recommended Version | Maximum Tested | Status |
|-----------|----------------|--------------------|--------------------|--------|
| Python | 3.11.0 | 3.12.4 | 3.12.x | Supported |
| FastAPI | 0.115.0 | 0.115.6 | 0.115.x | Supported |
| Uvicorn | 0.30.0 | 0.32.0 | 0.32.x | Supported |
| Pydantic | 2.7.0 | 2.10.0 | 2.10.x | Supported |
| OpenSearch | 2.11.0 | 2.17.0 | 2.17.x | Supported |
| Elasticsearch | 8.12.0 | 8.15.0 | 8.15.x | Supported |
| PostgreSQL | 15.0 | 16.4 | 16.x | Supported |
| Redis | 7.0.0 | 7.4.0 | 7.4.x | Supported |
| Kubernetes | 1.28.0 | 1.30.2 | 1.30.x | Supported |
| Terraform | 1.6.0 | 1.9.0 | 1.9.x | Supported |
| Helm | 3.13.0 | 3.16.0 | 3.16.x | Supported |
| Docker | 24.0.0 | 27.0.0 | 27.x | Supported |
| Docker Compose | 2.23.0 | 2.29.0 | 2.29.x | Supported |

### Notes

- **Python 3.11 vs 3.12:** Both are fully supported. Python 3.12 offers improved error messages and performance optimizations in the interpreter. The agent uses no features exclusive to 3.12, so 3.11 remains viable for environments with constraints.
- **FastAPI 0.115+:** Required for Pydantic v2 native support and the latest OpenAPI 3.1 schema generation. Versions below 0.115 use Pydantic v1 compatibility mode, which is not tested.
- **PostgreSQL 15 vs 16:** PostgreSQL 16 adds `pg_stat_io` for I/O monitoring and improved logical replication. Both versions work identically for agent schema requirements. Use PostgreSQL 16 for new deployments.
- **Redis 7.x:** Required for Redis Functions support used in alert deduplication. Redis 6.x is not supported due to missing `FUNCTION` commands.
- **Kubernetes 1.28-1.30:** The agent uses stable APIs only (`apps/v1`, `batch/v1`, `networking.k8s.io/v1`). No beta or alpha API dependencies. HPA v2 autoscaling is used, which is stable in all listed versions.
- **OpenSearch vs Elasticsearch:** The agent supports both. Configure via `SEARCH_ENGINE_TYPE` environment variable (`opensearch` or `elasticsearch`). Query DSL is compatible across both.

---

## Python Dependency Compatibility

| Package | Minimum Version | Recommended Version | Purpose |
|---------|----------------|--------------------|---------| 
| httpx | 0.27.0 | 0.28.0 | Async HTTP client for API integrations |
| sqlalchemy | 2.0.30 | 2.0.35 | Database ORM and query builder |
| alembic | 1.13.0 | 1.14.0 | Database migration management |
| celery | 5.4.0 | 5.4.0 | Distributed task queue for background jobs |
| redis[hiredis] | 5.0.0 | 5.2.0 | Redis client with C parser |
| pydantic-settings | 2.4.0 | 2.6.0 | Settings management from environment |
| python-jose[cryptography] | 3.3.0 | 3.3.0 | JWT token handling |
| prometheus-client | 0.21.0 | 0.21.0 | Metrics exposition |
| structlog | 24.1.0 | 24.4.0 | Structured logging |
| pymisp | 2.4.187 | 2.4.195 | MISP API client |
| falconpy | 1.4.0 | 1.4.5 | CrowdStrike Falcon API client |
| elasticsearch | 8.14.0 | 8.15.0 | Elasticsearch client |
| opensearch-py | 2.6.0 | 2.7.0 | OpenSearch client |
| azure-identity | 1.17.0 | 1.19.0 | Azure AD authentication |
| azure-mgmt-securityinsight | 2.0.0 | 2.0.0 | Microsoft Sentinel management |

---

## Cloud Provider Compatibility

### Amazon Web Services (AWS)

| Region | Tested | EKS Version | RDS PostgreSQL | ElastiCache Redis | Notes |
|--------|--------|-------------|----------------|-------------------|-------|
| us-east-1 (N. Virginia) | Yes | 1.30 | 16.4 | 7.1 | Primary recommended region. All services available. |
| us-west-2 (Oregon) | Yes | 1.30 | 16.4 | 7.1 | DR region. Full parity with us-east-1. |
| eu-west-1 (Ireland) | Yes | 1.30 | 16.4 | 7.1 | GDPR-compliant deployments. Data residency controls verified. |

**AWS Services Used:**
- EKS (Elastic Kubernetes Service) with managed node groups
- RDS PostgreSQL with Multi-AZ
- ElastiCache for Redis (cluster mode enabled)
- S3 for artifact and log storage
- KMS for encryption key management
- Secrets Manager for credential storage
- CloudWatch for log aggregation
- ALB (Application Load Balancer) with WAF
- VPC with private subnets, NAT gateways

### Microsoft Azure

| Region | Tested | AKS Version | Azure Database for PostgreSQL | Azure Cache for Redis | Notes |
|--------|--------|-------------|-------------------------------|----------------------|-------|
| eastus (East US) | Yes | 1.30 | 16 (Flexible Server) | 7.2 | Primary recommended region. |
| westeurope (Netherlands) | Yes | 1.30 | 16 (Flexible Server) | 7.2 | EU data residency compliance. GDPR-ready. |

**Azure Services Used:**
- AKS (Azure Kubernetes Service) with system and user node pools
- Azure Database for PostgreSQL Flexible Server with HA
- Azure Cache for Redis (Enterprise tier for Redis Functions)
- Azure Blob Storage for artifacts
- Azure Key Vault for secret management
- Azure Monitor / Log Analytics for observability
- Azure Application Gateway with WAF v2
- Azure Virtual Network with private endpoints

### Google Cloud Platform (GCP)

| Region | Tested | GKE Version | Cloud SQL PostgreSQL | Memorystore Redis | Notes |
|--------|--------|-------------|---------------------|-------------------|-------|
| us-central1 (Iowa) | Yes | 1.30 | 16 | 7.2 | Primary recommended region. |
| europe-west1 (Belgium) | Yes | 1.30 | 16 | 7.2 | EU data residency compliance. |

**GCP Services Used:**
- GKE (Google Kubernetes Engine) with Autopilot or Standard mode
- Cloud SQL for PostgreSQL with HA
- Memorystore for Redis
- Cloud Storage for artifacts
- Secret Manager for credential storage
- Cloud Monitoring and Cloud Logging
- Cloud Load Balancing with Cloud Armor WAF
- VPC with Private Google Access

---

## SIEM Platform Compatibility

| SIEM Platform | Minimum Version | Maximum Tested | Integration Method | Notes |
|--------------|----------------|----------------|-------------------|-------|
| Splunk Enterprise | 9.0.0 | 9.2.x | REST API | On-prem and Splunk Cloud supported |
| Splunk Cloud | Current | Current | REST API | Requires admin-managed tokens |
| Elastic Security | 8.10.0 | 8.15.x | REST API | Self-managed and Elastic Cloud |
| Microsoft Sentinel | N/A (SaaS) | Current (2023-11-01 API) | ARM REST API | Azure subscription required |
| OpenSearch Security Analytics | 2.11.0 | 2.17.x | REST API | AWS-managed or self-hosted |

---

## Browser Compatibility (Dashboard UI)

| Browser | Minimum Version | Notes |
|---------|----------------|-------|
| Google Chrome | 120+ | Recommended. Full feature support. |
| Mozilla Firefox | 120+ | Full feature support. |
| Microsoft Edge | 120+ | Chromium-based. Full feature support. |
| Safari | 17.0+ | Supported. Minor CSS differences in data tables. |

---

## Operating System Compatibility (Development / CI)

| OS | Version | Architecture | Status |
|----|---------|-------------|--------|
| Ubuntu | 22.04 LTS, 24.04 LTS | amd64, arm64 | Supported |
| Debian | 12 (Bookworm) | amd64, arm64 | Supported |
| Alpine | 3.19, 3.20 | amd64, arm64 | Container images only |
| macOS | 14 (Sonoma)+ | arm64 (Apple Silicon) | Development only |
| Windows | 11 | amd64 | Development only (WSL2 recommended) |

---

## Container Image Base

| Image | Tag | Size | Notes |
|-------|-----|------|-------|
| python | 3.12-slim-bookworm | ~150 MB | Production runtime |
| python | 3.12-bookworm | ~900 MB | Development/CI (includes build tools) |
| postgres | 16-alpine | ~80 MB | Local development database |
| redis | 7.4-alpine | ~30 MB | Local development cache |
