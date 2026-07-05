# Kubernetes Deployment Guide

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## 1. Namespace Setup

```bash
# Create the namespace
kubectl create namespace soc-agent

# Apply Pod Security Standards (restricted profile)
kubectl label namespace soc-agent \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/warn-version=latest \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/audit-version=latest

# Apply resource quota
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ResourceQuota
metadata:
  name: soc-agent-quota
  namespace: soc-agent
spec:
  hard:
    requests.cpu: "8"
    requests.memory: "16Gi"
    limits.cpu: "16"
    limits.memory: "32Gi"
    pods: "30"
    persistentvolumeclaims: "5"
    services: "10"
EOF

# Apply limit range for default pod resource constraints
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: LimitRange
metadata:
  name: soc-agent-limits
  namespace: soc-agent
spec:
  limits:
    - type: Container
      default:
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      max:
        cpu: "4"
        memory: "4Gi"
      min:
        cpu: "50m"
        memory: "64Mi"
EOF

# Verify namespace setup
kubectl get namespace soc-agent --show-labels
kubectl get resourcequota -n soc-agent
kubectl get limitrange -n soc-agent
```

---

## 2. Secret Creation

### 2.1 Option A: Direct Secret Creation (Development / Simple Deployments)

```bash
# Database credentials
kubectl create secret generic soc-agent-db \
  --namespace soc-agent \
  --from-literal=app-url="postgresql+asyncpg://soc_agent_app:APP_PASSWORD@db-host:5432/soc_analyst_agent?ssl=verify-full" \
  --from-literal=migrate-url="postgresql+asyncpg://soc_agent_migrate:MIGRATE_PASSWORD@db-host:5432/soc_analyst_agent?ssl=verify-full" \
  --from-literal=readonly-url="postgresql+asyncpg://soc_agent_readonly:READONLY_PASSWORD@db-host:5432/soc_analyst_agent?ssl=verify-full"

# Redis credentials
kubectl create secret generic soc-agent-redis \
  --namespace soc-agent \
  --from-literal=url="rediss://default:REDIS_PASSWORD@redis-host:6379/0" \
  --from-literal=celery-broker="rediss://default:REDIS_PASSWORD@redis-host:6379/1" \
  --from-literal=celery-backend="rediss://default:REDIS_PASSWORD@redis-host:6379/2"

# JWT signing key
kubectl create secret generic soc-agent-jwt \
  --namespace soc-agent \
  --from-file=private-key=./jwt-private.pem \
  --from-file=public-key=./jwt-public.pem

# SIEM credentials
kubectl create secret generic soc-agent-siem \
  --namespace soc-agent \
  --from-literal=splunk-token="SPLUNK_AUTH_TOKEN" \
  --from-literal=elastic-api-key="ELASTIC_API_KEY" \
  --from-literal=sentinel-tenant-id="AZURE_TENANT_ID" \
  --from-literal=sentinel-client-id="AZURE_CLIENT_ID" \
  --from-literal=sentinel-client-secret="AZURE_CLIENT_SECRET"

# Threat intelligence API keys
kubectl create secret generic soc-agent-ti \
  --namespace soc-agent \
  --from-literal=virustotal-key="VT_API_KEY" \
  --from-literal=abuseipdb-key="ABUSEIPDB_API_KEY" \
  --from-literal=misp-key="MISP_API_KEY" \
  --from-literal=crowdstrike-client-id="CS_CLIENT_ID" \
  --from-literal=crowdstrike-client-secret="CS_CLIENT_SECRET"

# Notification credentials
kubectl create secret generic soc-agent-notifications \
  --namespace soc-agent \
  --from-literal=pagerduty-key="PD_INTEGRATION_KEY" \
  --from-literal=slack-webhook="SLACK_WEBHOOK_URL"
```

### 2.2 Option B: External Secrets Operator (Recommended for Production)

```yaml
# Install External Secrets Operator first
# helm repo add external-secrets https://charts.external-secrets.io
# helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace

# Create SecretStore (example for AWS Secrets Manager)
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets
  namespace: soc-agent
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: soc-agent-api
---
# Create ExternalSecret
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: soc-agent-secrets
  namespace: soc-agent
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets
    kind: SecretStore
  target:
    name: soc-agent-secrets
    creationPolicy: Owner
  data:
    - secretKey: database-url
      remoteRef:
        key: soc-analyst-agent/database
        property: app-url
    - secretKey: redis-url
      remoteRef:
        key: soc-analyst-agent/redis
        property: url
    - secretKey: jwt-private-key
      remoteRef:
        key: soc-analyst-agent/jwt
        property: private-key
    - secretKey: splunk-token
      remoteRef:
        key: soc-analyst-agent/siem
        property: splunk-token
    - secretKey: virustotal-key
      remoteRef:
        key: soc-analyst-agent/ti
        property: virustotal-key
```

### 2.3 Verify Secrets

```bash
# List all secrets in the namespace
kubectl get secrets -n soc-agent

# Verify a secret has the expected keys (does not reveal values)
kubectl get secret soc-agent-db -n soc-agent -o jsonpath='{.data}' | python -c "import sys,json; print(list(json.load(sys.stdin).keys()))"
```

---

## 3. Helm Installation

### 3.1 Add Helm Repository (if using a chart repository)

```bash
# If chart is in a Helm repository
helm repo add soc-agent https://charts.company.com/soc-analyst-agent
helm repo update

# Or use the local chart from the repository
cd /path/to/soc-analyst-agent
```

### 3.2 Create Values File

Create `values-production.yaml`:

```yaml
replicaCount:
  api: 3
  worker: 4
  connector: 2
  beat: 1

image:
  repository: your-registry.com/soc-analyst-agent
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

imagePullSecrets:
  - name: registry-credentials

serviceAccount:
  create: true
  name: soc-agent-api
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::ACCOUNT_ID:role/soc-agent-pod-role"

service:
  type: ClusterIP
  port: 8000

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1s"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
  hosts:
    - host: soc-agent.company.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: soc-agent-tls
      hosts:
        - soc-agent.company.com

resources:
  api:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi
  worker:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 1Gi
  connector:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 512Mi

autoscaling:
  api:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
  worker:
    enabled: true
    minReplicas: 4
    maxReplicas: 20
    targetCPUUtilizationPercentage: 80

podDisruptionBudget:
  api:
    minAvailable: 2
  worker:
    minAvailable: 2

nodeSelector:
  kubernetes.io/os: linux

tolerations: []

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app
                operator: In
                values:
                  - soc-agent-api
          topologyKey: kubernetes.io/hostname

config:
  appEnv: production
  logLevel: INFO
  logFormat: json
  apiWorkers: 4
  correlationWindowHours: 24
  mitreMappingMinConfidence: 0.5
  alertRetentionDays: 365

siem:
  connectors:
    - type: splunk
      enabled: true
      pollIntervalSeconds: 30
    - type: elastic
      enabled: true
      pollIntervalSeconds: 30
    - type: sentinel
      enabled: true
      pollIntervalSeconds: 60

monitoring:
  prometheus:
    enabled: true
    port: 8000
    path: /metrics
  serviceMonitor:
    enabled: true
    interval: 30s

networkPolicy:
  enabled: true
```

### 3.3 Install the Chart

```bash
helm upgrade --install soc-analyst-agent \
  ./infrastructure/helm/soc-analyst-agent \
  --namespace soc-agent \
  --values values-production.yaml \
  --wait \
  --timeout 10m \
  --atomic
```

The `--atomic` flag ensures automatic rollback if the deployment fails.

---

## 4. Verify Pods Are Running

```bash
# Check pod status
kubectl get pods -n soc-agent -o wide

# Check all pods are ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=soc-analyst-agent \
  -n soc-agent --timeout=300s

# Check for any events indicating issues
kubectl get events -n soc-agent --sort-by='.lastTimestamp' | tail -20

# Check logs from each component
kubectl logs -n soc-agent -l component=api --tail=50
kubectl logs -n soc-agent -l component=worker --tail=50
kubectl logs -n soc-agent -l component=connector --tail=50
kubectl logs -n soc-agent -l component=beat --tail=50

# Verify services
kubectl get svc -n soc-agent

# Verify ingress
kubectl get ingress -n soc-agent

# Test internal connectivity
kubectl run test-curl --rm -it --image=curlimages/curl --restart=Never -n soc-agent -- \
  curl -s http://soc-agent-api:8000/health
```

---

## 5. Configure Horizontal Pod Autoscaler (HPA)

HPA is configured via the Helm chart values (see section 3.2). Verify it is functioning:

```bash
# Check HPA status
kubectl get hpa -n soc-agent

# Expected output:
# NAME              REFERENCE                    TARGETS   MINPODS   MAXPODS   REPLICAS
# soc-agent-api     Deployment/soc-agent-api     25%/70%   3         10        3
# soc-agent-worker  Deployment/soc-agent-worker  15%/80%   4         20        4

# Describe HPA for detailed status
kubectl describe hpa soc-agent-api -n soc-agent

# Verify metrics server is providing data
kubectl top pods -n soc-agent
```

### Custom Metrics HPA (Optional)

For scaling based on alert queue depth instead of CPU:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: soc-agent-worker-custom
  namespace: soc-agent
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: soc-agent-worker
  minReplicas: 4
  maxReplicas: 20
  metrics:
    - type: Pods
      pods:
        metric:
          name: soc_agent_alert_queue_depth
        target:
          type: AverageValue
          averageValue: "100"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Pods
          value: 4
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Pods
          value: 2
          periodSeconds: 120
```

---

## 6. Set Up Monitoring

### 6.1 ServiceMonitor for Prometheus

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: soc-agent-monitor
  namespace: soc-agent
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: soc-analyst-agent
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
      scrapeTimeout: 10s
```

### 6.2 PrometheusRule for Alerts

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: soc-agent-alerts
  namespace: soc-agent
  labels:
    release: prometheus
spec:
  groups:
    - name: soc-agent
      rules:
        - alert: SOCAgentHighErrorRate
          expr: |
            rate(soc_agent_http_requests_total{status=~"5.."}[5m])
            / rate(soc_agent_http_requests_total[5m]) > 0.05
          for: 5m
          labels:
            severity: critical
            team: soc-platform
          annotations:
            summary: "SOC Agent API error rate above 5%"
            description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes."

        - alert: SOCAgentHighAlertBacklog
          expr: soc_agent_alert_queue_depth > 5000
          for: 10m
          labels:
            severity: warning
            team: soc-platform
          annotations:
            summary: "SOC Agent alert queue backlog exceeds 5,000"
            description: "Current queue depth: {{ $value }}. Processing may be delayed."

        - alert: SOCAgentSIEMDisconnected
          expr: soc_agent_siem_connected == 0
          for: 5m
          labels:
            severity: critical
            team: soc-platform
          annotations:
            summary: "SOC Agent lost connection to SIEM"
            description: "SIEM connector has been disconnected for more than 5 minutes."

        - alert: SOCAgentDatabaseConnectionPoolExhausted
          expr: soc_agent_db_pool_available == 0
          for: 2m
          labels:
            severity: critical
            team: soc-platform
          annotations:
            summary: "SOC Agent database connection pool exhausted"
            description: "No available database connections. API requests will fail."

        - alert: SOCAgentPodRestarting
          expr: increase(kube_pod_container_status_restarts_total{namespace="soc-agent"}[1h]) > 3
          for: 5m
          labels:
            severity: warning
            team: soc-platform
          annotations:
            summary: "SOC Agent pod restarting frequently"
            description: "Pod {{ $labels.pod }} has restarted {{ $value }} times in the last hour."
```

### 6.3 Import Grafana Dashboard

```bash
# Import the pre-built Grafana dashboard
# The dashboard JSON is located at infrastructure/grafana/soc-agent-dashboard.json

# Using Grafana API:
curl -X POST https://grafana.company.com/api/dashboards/db \
  -H "Authorization: Bearer GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  -d @infrastructure/grafana/soc-agent-dashboard.json

# Or import via Grafana UI: Dashboards > Import > Upload JSON
```

### 6.4 PagerDuty AlertManager Integration

```yaml
# In AlertManager config (alertmanager.yml)
receivers:
  - name: soc-platform-pagerduty
    pagerduty_configs:
      - service_key: "PAGERDUTY_INTEGRATION_KEY"
        severity: '{{ if eq .Labels.severity "critical" }}critical{{ else }}warning{{ end }}'
        description: '{{ .Annotations.summary }}'
        details:
          firing: '{{ .Annotations.description }}'

route:
  receiver: soc-platform-pagerduty
  routes:
    - match:
        team: soc-platform
      receiver: soc-platform-pagerduty
      group_wait: 30s
      group_interval: 5m
      repeat_interval: 4h
```

---

## 7. Network Policy

```bash
# Apply network policies
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: soc-agent
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-ingress
  namespace: soc-agent
spec:
  podSelector:
    matchLabels:
      component: api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - port: 8000
          protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress
  namespace: soc-agent
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # DNS
    - to: []
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # PostgreSQL
    - to:
        - ipBlock:
            cidr: DB_HOST_CIDR/32
      ports:
        - port: 5432
          protocol: TCP
    # Redis
    - to:
        - ipBlock:
            cidr: REDIS_HOST_CIDR/32
      ports:
        - port: 6379
          protocol: TCP
    # External HTTPS (SIEM, TI APIs)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - port: 443
          protocol: TCP
        - port: 8089
          protocol: TCP
    # Intra-namespace communication
    - to:
        - podSelector: {}
EOF

# Verify policies
kubectl get networkpolicy -n soc-agent
```

---

## 8. Validation Checklist

After completing all steps, verify:

- [ ] All pods in `soc-agent` namespace are `Running` and `Ready`
- [ ] HPA is reporting current metrics and target thresholds
- [ ] Health endpoint returns `healthy` for all components
- [ ] Ingress is routing traffic to the API
- [ ] TLS certificate is valid and not self-signed
- [ ] Prometheus is scraping metrics from agent pods
- [ ] Grafana dashboard is populated with data
- [ ] AlertManager rules are loaded (check Prometheus UI > Alerts)
- [ ] Network policies are enforced (test with a pod that should be blocked)
- [ ] PagerDuty test alert was received
- [ ] Logs are flowing to the cluster log aggregator
