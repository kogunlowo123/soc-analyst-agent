# Production Deployment Guide

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## 1. Pre-Deployment Checklist

Complete every item before proceeding with production deployment. Do not skip items.

### Infrastructure

- [ ] Kubernetes cluster is provisioned with minimum 3 worker nodes (8 vCPUs, 16 GB RAM each)
- [ ] Kubernetes version is 1.28, 1.29, or 1.30
- [ ] Ingress controller (NGINX, ALB, or Traefik) is installed and functioning
- [ ] Metrics Server is deployed (`kubectl top nodes` returns data)
- [ ] Default StorageClass is configured with a dynamic volume provisioner
- [ ] Container registry contains the agent image at the target version tag

### Database and Cache

- [ ] PostgreSQL 15 or 16 is accessible from the cluster with TLS enabled
- [ ] PostgreSQL databases created: `soc_analyst_agent`
- [ ] PostgreSQL users created: `soc_agent_app` (DML), `soc_agent_migrate` (DDL), `soc_agent_readonly` (read-only)
- [ ] Redis 7.x is accessible from the cluster with TLS enabled
- [ ] Redis `maxmemory` is set to at least 2 GB with `maxmemory-policy allkeys-lru`

### Secrets and Configuration

- [ ] All secrets are stored in the secret manager (Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager)
- [ ] SIEM API credentials are provisioned and tested manually (`curl` or Postman)
- [ ] Threat intelligence API keys are provisioned and tested
- [ ] JWT RSA key pair (4096-bit) is generated and stored in the secret manager
- [ ] OAuth provider is configured with the agent's redirect URI

### Network

- [ ] Firewall rules allow agent pods to reach SIEM API endpoints
- [ ] Firewall rules allow agent pods to reach TI API endpoints (HTTPS 443)
- [ ] DNS record for the agent dashboard is created (e.g., `soc-agent.company.com`)
- [ ] TLS certificate is provisioned for the dashboard domain
- [ ] NetworkPolicy resources are prepared for the agent namespace

### Monitoring

- [ ] Prometheus is deployed and scraping the cluster
- [ ] Grafana is deployed with dashboard import capability
- [ ] AlertManager is configured with notification channels
- [ ] PagerDuty service and integration key are created for agent alerts

---

## 2. Production Configuration

### 2.1 Environment Variables

Create a Kubernetes ConfigMap or populate from the secret manager.

```yaml
# Application
APP_ENV: "production"
APP_DEBUG: "false"
APP_LOG_LEVEL: "INFO"
APP_LOG_FORMAT: "json"

# API Server
API_HOST: "0.0.0.0"
API_PORT: "8000"
API_WORKERS: "4"
API_TIMEOUT: "60"

# Database
DATABASE_URL: "postgresql+asyncpg://soc_agent_app:PASSWORD@db-host:5432/soc_analyst_agent?ssl=verify-full"
DATABASE_POOL_SIZE: "20"
DATABASE_MAX_OVERFLOW: "10"
DATABASE_POOL_TIMEOUT: "30"

# Redis
REDIS_URL: "rediss://default:PASSWORD@redis-host:6379/0"
CELERY_BROKER_URL: "rediss://default:PASSWORD@redis-host:6379/1"
CELERY_RESULT_BACKEND: "rediss://default:PASSWORD@redis-host:6379/2"

# JWT
JWT_ALGORITHM: "RS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES: "60"
JWT_REFRESH_TOKEN_EXPIRE_DAYS: "7"

# SIEM (configure one or more)
SPLUNK_BASE_URL: "https://splunk.company.com:8089"
SPLUNK_TOKEN: "FROM_SECRET_MANAGER"
SPLUNK_VERIFY_SSL: "true"

ELASTIC_BASE_URL: "https://kibana.company.com:5601"
ELASTIC_API_KEY: "FROM_SECRET_MANAGER"
ELASTIC_VERIFY_SSL: "true"

SENTINEL_TENANT_ID: "FROM_SECRET_MANAGER"
SENTINEL_CLIENT_ID: "FROM_SECRET_MANAGER"
SENTINEL_CLIENT_SECRET: "FROM_SECRET_MANAGER"
SENTINEL_SUBSCRIPTION_ID: "your-subscription-id"
SENTINEL_RESOURCE_GROUP: "rg-sentinel"
SENTINEL_WORKSPACE_NAME: "sentinel-workspace"

# Threat Intelligence
VIRUSTOTAL_API_KEY: "FROM_SECRET_MANAGER"
ABUSEIPDB_API_KEY: "FROM_SECRET_MANAGER"
MISP_URL: "https://misp.company.com"
MISP_API_KEY: "FROM_SECRET_MANAGER"
CROWDSTRIKE_CLIENT_ID: "FROM_SECRET_MANAGER"
CROWDSTRIKE_CLIENT_SECRET: "FROM_SECRET_MANAGER"
CROWDSTRIKE_BASE_URL: "https://api.crowdstrike.com"

# Enrichment
ENRICHMENT_CACHE_TTL_SECONDS: "3600"
ENRICHMENT_MAX_RETRIES: "3"

# Correlation
CORRELATION_WINDOW_HOURS: "24"
MITRE_MAPPING_MIN_CONFIDENCE: "0.5"

# Notifications
PAGERDUTY_INTEGRATION_KEY: "FROM_SECRET_MANAGER"
SLACK_WEBHOOK_URL: "FROM_SECRET_MANAGER"

# Data Retention
ALERT_RETENTION_DAYS: "365"
AUDIT_LOG_RETENTION_DAYS: "730"
```

### 2.2 Resource Requests and Limits

```yaml
# API Server
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2000m"
    memory: "2Gi"

# Celery Worker
resources:
  requests:
    cpu: "250m"
    memory: "256Mi"
  limits:
    cpu: "1000m"
    memory: "1Gi"

# SIEM Connector
resources:
  requests:
    cpu: "250m"
    memory: "256Mi"
  limits:
    cpu: "1000m"
    memory: "512Mi"
```

---

## 3. Database Migration

Run database migrations before starting the application.

```bash
# Step 1: Verify database connectivity
kubectl run pg-test --rm -it --image=postgres:16-alpine --restart=Never -- \
  psql "postgresql://soc_agent_migrate:PASSWORD@db-host:5432/soc_analyst_agent?sslmode=verify-full" \
  -c "SELECT version();"

# Step 2: Run migrations via Kubernetes Job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: soc-agent-migrate
  namespace: soc-agent
spec:
  template:
    spec:
      serviceAccountName: soc-agent-api
      containers:
        - name: migrate
          image: your-registry/soc-analyst-agent:v1.0.0
          command: ["alembic", "upgrade", "head"]
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: soc-agent-db-credentials
                  key: migration-url
      restartPolicy: Never
  backoffLimit: 3
EOF

# Step 3: Verify migration completed
kubectl logs job/soc-agent-migrate -n soc-agent

# Step 4: Verify schema
kubectl run pg-verify --rm -it --image=postgres:16-alpine --restart=Never -- \
  psql "postgresql://soc_agent_readonly:PASSWORD@db-host:5432/soc_analyst_agent?sslmode=verify-full" \
  -c "\dt"
```

---

## 4. Deployment Steps

### Step 1: Create Namespace and Secrets

```bash
# Create namespace
kubectl create namespace soc-agent

# Label namespace for Pod Security Standards
kubectl label namespace soc-agent \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted

# Create secrets (example for direct creation; prefer External Secrets Operator)
kubectl create secret generic soc-agent-secrets \
  --namespace soc-agent \
  --from-literal=database-url="postgresql+asyncpg://..." \
  --from-literal=redis-url="rediss://..." \
  --from-literal=jwt-private-key="$(cat jwt-private.pem)" \
  --from-literal=splunk-token="..." \
  --from-literal=virustotal-api-key="..." \
  --from-literal=abuseipdb-api-key="..." \
  --from-literal=pagerduty-key="..."
```

### Step 2: Deploy via Helm

```bash
helm upgrade --install soc-analyst-agent ./infrastructure/helm/soc-analyst-agent \
  --namespace soc-agent \
  --values ./infrastructure/helm/soc-analyst-agent/values-production.yaml \
  --set image.tag=v1.0.0 \
  --wait \
  --timeout 10m
```

### Step 3: Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n soc-agent -o wide

# Expected output:
# soc-agent-api-xxx        1/1  Running  0  1m
# soc-agent-api-xxx        1/1  Running  0  1m
# soc-agent-worker-xxx     1/1  Running  0  1m
# soc-agent-worker-xxx     1/1  Running  0  1m
# soc-agent-connector-xxx  1/1  Running  0  1m
# soc-agent-beat-xxx       1/1  Running  0  1m

# Check no pending or crash-looping pods
kubectl get pods -n soc-agent --field-selector=status.phase!=Running
```

---

## 5. Health Check Verification

### 5.1 Liveness and Readiness Probes

```bash
# API health endpoint
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -s http://localhost:8000/health | python -m json.tool

# Expected response:
# {
#   "status": "healthy",
#   "version": "1.0.0",
#   "checks": {
#     "database": "connected",
#     "redis": "connected",
#     "siem_splunk": "connected",
#     "siem_elastic": "connected",
#     "siem_sentinel": "connected"
#   }
# }

# Readiness probe (returns 200 when ready to receive traffic)
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/ready
# Expected: 200
```

### 5.2 External Access

```bash
# Test via ingress
curl -s https://soc-agent.company.com/health | python -m json.tool

# Verify TLS certificate
openssl s_client -connect soc-agent.company.com:443 -servername soc-agent.company.com < /dev/null 2>/dev/null | openssl x509 -noout -dates
```

---

## 6. Smoke Test Procedures

Run these tests after every production deployment to verify end-to-end functionality.

### 6.1 Authentication

```bash
# Obtain JWT token
TOKEN=$(curl -s -X POST https://soc-agent.company.com/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "smoke-test-user", "password": "FROM_SECRET_MANAGER"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token obtained: ${TOKEN:0:20}..."
```

### 6.2 Alert Retrieval

```bash
# List recent alerts
curl -s -H "Authorization: Bearer $TOKEN" \
  https://soc-agent.company.com/api/v1/alerts?limit=5 | python -m json.tool

# Verify response contains alert data
```

### 6.3 Enrichment

```bash
# Enrich a known-safe IP
curl -s -H "Authorization: Bearer $TOKEN" \
  https://soc-agent.company.com/api/v1/enrich/ip/8.8.8.8 | python -m json.tool

# Verify response contains VirusTotal and AbuseIPDB data
```

### 6.4 Dashboard Access

```bash
# Verify dashboard loads
curl -s -o /dev/null -w "%{http_code}" https://soc-agent.company.com/

# Expected: 200
```

### 6.5 Metrics Endpoint

```bash
# Verify Prometheus metrics
curl -s http://soc-agent-api.soc-agent.svc.cluster.local:8000/metrics | head -20

# Verify key metrics exist:
# soc_agent_alerts_processed_total
# soc_agent_enrichment_requests_total
# soc_agent_alert_queue_depth
```

---

## 7. Rollback Procedure

If smoke tests fail or issues are discovered after deployment:

### 7.1 Helm Rollback

```bash
# List release history
helm history soc-analyst-agent -n soc-agent

# Rollback to previous version
helm rollback soc-analyst-agent [REVISION_NUMBER] -n soc-agent --wait --timeout 5m

# Verify rollback
kubectl get pods -n soc-agent
helm status soc-analyst-agent -n soc-agent
```

### 7.2 Database Rollback

If the migration introduced breaking schema changes:

```bash
# Identify current migration version
kubectl run pg-check --rm -it --image=postgres:16-alpine --restart=Never -- \
  psql "$DATABASE_URL" -c "SELECT version_num FROM alembic_version;"

# Rollback to specific migration
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: soc-agent-rollback
  namespace: soc-agent
spec:
  template:
    spec:
      serviceAccountName: soc-agent-api
      containers:
        - name: rollback
          image: your-registry/soc-analyst-agent:PREVIOUS_VERSION_TAG
          command: ["alembic", "downgrade", "PREVIOUS_REVISION_ID"]
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: soc-agent-db-credentials
                  key: migration-url
      restartPolicy: Never
  backoffLimit: 1
EOF
```

### 7.3 Rollback Decision Matrix

| Symptom | Action |
|---------|--------|
| Pods crash-looping, no schema changes | Helm rollback |
| Health checks failing, no schema changes | Helm rollback |
| Database migration failed (no data written) | Alembic downgrade + Helm rollback |
| Database migration succeeded but app broken | Alembic downgrade + Helm rollback |
| Data corruption detected | STOP. Do not rollback automatically. Engage database team for point-in-time recovery. |

---

## 8. Post-Deployment Verification

After successful deployment and smoke tests:

1. Monitor Grafana dashboards for 30 minutes, watching for error rate spikes.
2. Verify Celery workers are processing alerts (check `soc_agent_alerts_processed_total` metric).
3. Verify SIEM connector is pulling alerts (check `soc_agent_siem_poll_success_total` metric).
4. Verify enrichment is functioning (check `soc_agent_enrichment_requests_total` metric).
5. Have a SOC analyst log in to the dashboard and verify alert visibility.
6. Review application logs for any ERROR or WARNING entries: `kubectl logs -n soc-agent -l app=soc-agent-api --since=30m | grep -E "ERROR|WARNING"`.
7. Confirm PagerDuty test notification was received.
