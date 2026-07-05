# Kubernetes Architecture

## Overview

The SOC Analyst Agent is deployed on a managed Kubernetes cluster (EKS) with strict namespace isolation, network policies, horizontal pod autoscaling, and security-hardened configurations. Each component runs as a separate Deployment with dedicated ServiceAccounts, resource limits, and pod disruption budgets.

## Namespace Architecture

```mermaid
graph TB
    subgraph Cluster["EKS Cluster: soc-agent-prod"]
        subgraph ns_ingress["Namespace: ingress-nginx"]
            ingress_ctrl["Ingress Controller<br/>nginx-ingress 1.9<br/>Replicas: 2<br/>Port: 80, 443"]
            cert_manager["cert-manager<br/>v1.14<br/>Let's Encrypt issuer<br/>Auto TLS renewal"]
        end

        subgraph ns_app["Namespace: soc-agent"]
            subgraph deployments["Deployments"]
                api_deploy["fastapi-api<br/>Replicas: 3<br/>Port: 8000<br/>CPU: 500m-1000m<br/>Mem: 512Mi-1Gi"]
                dashboard_deploy["nextjs-dashboard<br/>Replicas: 2<br/>Port: 3000<br/>CPU: 250m-500m<br/>Mem: 256Mi-512Mi"]
                agent_deploy["agent-engine<br/>Replicas: 2<br/>Port: 50051<br/>CPU: 1000m-2000m<br/>Mem: 2Gi-4Gi"]
                rag_deploy["rag-pipeline<br/>Replicas: 2<br/>Port: 8001<br/>CPU: 500m-1000m<br/>Mem: 1Gi-2Gi"]
                mcp_deploy["mcp-server<br/>Replicas: 2<br/>Port: 8002<br/>CPU: 500m-1000m<br/>Mem: 512Mi-1Gi"]
                a2a_deploy["a2a-handler<br/>Replicas: 2<br/>Port: 8003<br/>CPU: 250m-500m<br/>Mem: 256Mi-512Mi"]
            end

            subgraph workers["Worker Deployments"]
                celery_default["celery-default-worker<br/>Replicas: 3<br/>CPU: 500m-1000m<br/>Mem: 1Gi-2Gi"]
                celery_critical["celery-critical-worker<br/>Replicas: 2<br/>CPU: 500m-1000m<br/>Mem: 1Gi-2Gi"]
                celery_beat["celery-beat<br/>Replicas: 1<br/>CPU: 100m-250m<br/>Mem: 128Mi-256Mi"]
            end

            subgraph services["Services"]
                api_svc["svc/fastapi-api<br/>ClusterIP<br/>Port: 8000"]
                dashboard_svc["svc/nextjs-dashboard<br/>ClusterIP<br/>Port: 3000"]
                agent_svc["svc/agent-engine<br/>ClusterIP<br/>Port: 50051"]
                rag_svc["svc/rag-pipeline<br/>ClusterIP<br/>Port: 8001"]
                mcp_svc["svc/mcp-server<br/>ClusterIP<br/>Port: 8002"]
                a2a_svc["svc/a2a-handler<br/>ClusterIP<br/>Port: 8003"]
            end

            subgraph configs["Configuration"]
                cm_app["ConfigMap: app-config<br/>SIEM endpoints<br/>Correlation windows<br/>Severity thresholds"]
                cm_mitre["ConfigMap: mitre-config<br/>ATT&CK version<br/>Technique mappings<br/>Tactic definitions"]
                secret_db["Secret: db-credentials<br/>POSTGRES_HOST<br/>POSTGRES_PASSWORD<br/>POSTGRES_DB"]
                secret_redis["Secret: redis-credentials<br/>REDIS_URL<br/>REDIS_PASSWORD"]
                secret_api["Secret: api-keys<br/>VT_API_KEY<br/>ABUSEIPDB_KEY<br/>MISP_KEY<br/>OPENAI_API_KEY"]
                secret_siem["Secret: siem-credentials<br/>SPLUNK_TOKEN<br/>ELASTIC_API_KEY<br/>SENTINEL_CLIENT_SECRET"]
            end
        end

        subgraph ns_monitoring["Namespace: monitoring"]
            prometheus["Prometheus<br/>v2.48<br/>Scrape interval: 15s<br/>Retention: 15d"]
            grafana["Grafana<br/>v10.2<br/>SOC dashboards<br/>Port: 3000"]
            alertmanager["AlertManager<br/>v0.27<br/>PagerDuty integration"]
        end

        subgraph ns_logging["Namespace: logging"]
            fluentbit["Fluent Bit<br/>DaemonSet<br/>Log collection<br/>OpenSearch output"]
        end
    end

    ingress_ctrl -->|Route /api/*| api_svc
    ingress_ctrl -->|Route /| dashboard_svc
    ingress_ctrl -->|Route /a2a/*| a2a_svc

    api_svc --> api_deploy
    dashboard_svc --> dashboard_deploy
    agent_svc --> agent_deploy
    rag_svc --> rag_deploy
    mcp_svc --> mcp_deploy
    a2a_svc --> a2a_deploy

    api_deploy --> agent_svc
    api_deploy --> rag_svc
    agent_deploy --> mcp_svc
    agent_deploy --> rag_svc
    agent_deploy --> a2a_svc

    prometheus -->|Scrape /metrics| api_deploy
    prometheus -->|Scrape /metrics| agent_deploy
    prometheus -->|Scrape /metrics| celery_default
    fluentbit -->|Collect stdout/stderr| deployments
    fluentbit -->|Collect stdout/stderr| workers

    style ns_ingress fill:#fff3e0,stroke:#f57c00
    style ns_app fill:#e8f5e9,stroke:#388e3c
    style ns_monitoring fill:#e3f2fd,stroke:#1565c0
    style ns_logging fill:#f3e5f5,stroke:#7b1fa2
```

## Deployment Specifications

### FastAPI API Gateway

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-api
  namespace: soc-agent
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      serviceAccountName: fastapi-api-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: api
          image: <ecr>/soc-agent/api:1.0.0
          ports:
            - containerPort: 8000
              protocol: TCP
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: "1"
              memory: 1Gi
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 15
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          envFrom:
            - configMapRef:
                name: app-config
            - secretRef:
                name: db-credentials
            - secretRef:
                name: redis-credentials
```

## Horizontal Pod Autoscaler (HPA) Configuration

```mermaid
graph LR
    subgraph HPA_Rules["HPA Configurations"]
        hpa_api["HPA: fastapi-api<br/>Min: 3 / Max: 10<br/>CPU Target: 70%<br/>Memory Target: 80%<br/>Scale-up: 1 pod/60s<br/>Scale-down: 1 pod/300s"]
        hpa_agent["HPA: agent-engine<br/>Min: 2 / Max: 8<br/>CPU Target: 60%<br/>Custom: queue_depth < 50<br/>Scale-up: 1 pod/120s<br/>Scale-down: 1 pod/600s"]
        hpa_worker["HPA: celery-default-worker<br/>Min: 3 / Max: 15<br/>Custom: celery_queue_length<br/>Target: < 100 tasks<br/>Scale-up: 2 pods/60s<br/>Scale-down: 1 pod/300s"]
        hpa_rag["HPA: rag-pipeline<br/>Min: 2 / Max: 6<br/>CPU Target: 70%<br/>Scale-up: 1 pod/120s<br/>Scale-down: 1 pod/600s"]
    end
```

| Deployment | Min | Max | CPU Target | Custom Metric | Scale-Up Rate | Scale-Down Rate |
|------------|-----|-----|------------|---------------|---------------|-----------------|
| fastapi-api | 3 | 10 | 70% | Request latency p99 < 500ms | 1 pod / 60s | 1 pod / 300s |
| agent-engine | 2 | 8 | 60% | Investigation queue depth < 50 | 1 pod / 120s | 1 pod / 600s |
| celery-default-worker | 3 | 15 | - | Celery queue length < 100 | 2 pods / 60s | 1 pod / 300s |
| celery-critical-worker | 2 | 8 | - | Critical queue length < 10 | 1 pod / 30s | 1 pod / 600s |
| rag-pipeline | 2 | 6 | 70% | - | 1 pod / 120s | 1 pod / 600s |
| mcp-server | 2 | 6 | 70% | - | 1 pod / 120s | 1 pod / 600s |
| a2a-handler | 2 | 4 | 70% | - | 1 pod / 120s | 1 pod / 600s |

## Pod Disruption Budgets (PDB)

| Deployment | minAvailable | maxUnavailable | Rationale |
|------------|-------------|----------------|-----------|
| fastapi-api | 2 | - | Maintain API availability during node drain |
| agent-engine | 1 | - | At least one engine instance for active investigations |
| celery-critical-worker | 1 | - | Critical alert processing must continue |
| celery-default-worker | - | 1 | Allow one worker to be drained at a time |
| nextjs-dashboard | 1 | - | Dashboard availability for SOC analysts |
| celery-beat | 1 | 0 | Single instance, must not be disrupted |

## Network Policies

```mermaid
graph TD
    subgraph NetworkPolicies["Network Policy Rules"]
        np_api["NetworkPolicy: api-policy<br/>Ingress: ingress-nginx namespace (TCP/8000)<br/>Egress: agent-engine (TCP/50051),<br/>rag-pipeline (TCP/8001),<br/>PostgreSQL (TCP/5432),<br/>Redis (TCP/6379),<br/>OpenSearch (TCP/9200)"]

        np_agent["NetworkPolicy: agent-engine-policy<br/>Ingress: fastapi-api (TCP/50051)<br/>Egress: rag-pipeline (TCP/8001),<br/>mcp-server (TCP/8002),<br/>a2a-handler (TCP/8003),<br/>Redis (TCP/6379),<br/>LLM API (TCP/443)"]

        np_mcp["NetworkPolicy: mcp-server-policy<br/>Ingress: agent-engine (TCP/8002)<br/>Egress: SIEM endpoints (TCP/8089,9200,443),<br/>Threat Intel APIs (TCP/443)"]

        np_worker["NetworkPolicy: celery-worker-policy<br/>Ingress: None (pull-based)<br/>Egress: Redis (TCP/6379),<br/>PostgreSQL (TCP/5432),<br/>SIEM endpoints (TCP/8089,9200,443),<br/>Threat Intel APIs (TCP/443),<br/>Ticketing APIs (TCP/443)"]

        np_db["NetworkPolicy: database-policy<br/>Ingress: soc-agent namespace (TCP/5432,6379,9200)<br/>Egress: None (deny all)"]

        np_a2a["NetworkPolicy: a2a-policy<br/>Ingress: ingress-nginx (TCP/8003),<br/>agent-engine (TCP/8003)<br/>Egress: Peer agent endpoints (TCP/443)"]
    end
```

## ServiceAccount and RBAC

| ServiceAccount | Namespace | IAM Role (IRSA) | Permissions |
|----------------|-----------|-----------------|-------------|
| fastapi-api-sa | soc-agent | soc-agent-api-role | Secrets Manager read, S3 read/write, CloudWatch put-metric |
| agent-engine-sa | soc-agent | soc-agent-engine-role | Secrets Manager read, S3 read |
| celery-worker-sa | soc-agent | soc-agent-worker-role | Secrets Manager read, S3 read/write, SES send-email |
| rag-pipeline-sa | soc-agent | soc-agent-rag-role | S3 read (knowledge base bucket), Secrets Manager read |
| mcp-server-sa | soc-agent | soc-agent-mcp-role | Secrets Manager read (SIEM, threat intel credentials) |
| a2a-handler-sa | soc-agent | soc-agent-a2a-role | Secrets Manager read, S3 read |
| prometheus-sa | monitoring | soc-agent-monitoring-role | CloudWatch read, EKS read |
| fluentbit-sa | logging | soc-agent-logging-role | OpenSearch write, CloudWatch put-log |

## ConfigMaps

### app-config

| Key | Value | Description |
|-----|-------|-------------|
| `SIEM_POLL_INTERVAL` | `60` | Seconds between SIEM polling cycles |
| `CORRELATION_WINDOW` | `14400` | Correlation time window in seconds (4 hours) |
| `SEVERITY_THRESHOLD_CRITICAL` | `90` | Score threshold for Critical severity |
| `SEVERITY_THRESHOLD_HIGH` | `70` | Score threshold for High severity |
| `SEVERITY_THRESHOLD_MEDIUM` | `40` | Score threshold for Medium severity |
| `DEDUP_WINDOW` | `900` | Deduplication window in seconds (15 minutes) |
| `MAX_CONCURRENT_ENRICHMENTS` | `20` | Maximum parallel IOC enrichment requests |
| `IOC_CACHE_TTL` | `3600` | IOC enrichment cache TTL in seconds |
| `LLM_MODEL` | `gpt-4o` | Primary LLM model for agent reasoning |
| `LLM_FALLBACK_MODEL` | `gpt-4o-mini` | Fallback model on primary failure |
| `LLM_MAX_TOKENS` | `4096` | Maximum output tokens per LLM call |
| `RAG_TOP_K` | `5` | Number of RAG retrieval results |

### mitre-config

| Key | Value | Description |
|-----|-------|-------------|
| `ATTACK_VERSION` | `15.1` | MITRE ATT&CK version for technique data |
| `ATTACK_STIX_URL` | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` | STIX data source |
| `CONFIDENCE_HIGH_THRESHOLD` | `0.8` | Minimum confidence for High mapping |
| `CONFIDENCE_MEDIUM_THRESHOLD` | `0.5` | Minimum confidence for Medium mapping |

## Secrets Management

All secrets are stored in AWS Secrets Manager and synced to Kubernetes Secrets via External Secrets Operator (ESO) with a 60-second refresh interval.

```mermaid
graph LR
    sm["AWS Secrets Manager<br/>30-day rotation"] -->|ExternalSecret CRD| eso["External Secrets Operator<br/>v0.9"]
    eso -->|Syncs to| k8s_secret["K8s Secret<br/>soc-agent namespace"]
    k8s_secret -->|Mounted as env vars| pods["Application Pods"]

    style sm fill:#fff3e0,stroke:#f57c00
    style eso fill:#e8f5e9,stroke:#388e3c
    style k8s_secret fill:#fce4ec,stroke:#c62828
```

| Secret Name | Keys | Rotation |
|-------------|------|----------|
| db-credentials | `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | 30 days |
| redis-credentials | `REDIS_URL`, `REDIS_PASSWORD` | 30 days |
| api-keys | `VT_API_KEY`, `ABUSEIPDB_KEY`, `MISP_KEY`, `MISP_URL`, `SHODAN_API_KEY`, `OTX_API_KEY` | 90 days |
| siem-credentials | `SPLUNK_URL`, `SPLUNK_TOKEN`, `ELASTIC_URL`, `ELASTIC_API_KEY`, `SENTINEL_TENANT_ID`, `SENTINEL_CLIENT_ID`, `SENTINEL_CLIENT_SECRET` | 90 days |
| llm-credentials | `OPENAI_API_KEY`, `OPENAI_ORG_ID` | 90 days |
| jwt-secrets | `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET` | 30 days |

## Ingress Configuration

| Host | Path | Service | Port | TLS | Rate Limit |
|------|------|---------|------|-----|------------|
| `soc.example.com` | `/` | nextjs-dashboard | 3000 | Yes (cert-manager) | 200 req/min |
| `soc.example.com` | `/api/v1/*` | fastapi-api | 8000 | Yes (cert-manager) | 100 req/min |
| `soc.example.com` | `/ws/*` | fastapi-api | 8000 | Yes (WebSocket upgrade) | 50 conn/min |
| `soc.example.com` | `/a2a/*` | a2a-handler | 8003 | Yes (mTLS) | 50 req/min |
| `soc.example.com` | `/metrics` | Deny (internal only) | - | - | - |
