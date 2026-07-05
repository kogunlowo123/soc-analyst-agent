# Monitoring Guide

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## 1. Prometheus Metrics

The SOC Analyst Agent exposes Prometheus metrics at `GET /metrics` on port 8000.

### 1.1 Key Metrics to Watch

#### Alert Processing

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|----------------|
| `soc_agent_alerts_ingested_total` | Counter | Total alerts ingested from all SIEM sources | N/A (informational) |
| `soc_agent_alerts_processed_total` | Counter | Total alerts fully processed (enriched, mapped, stored) | Flatline for >5 min = issue |
| `soc_agent_alerts_deduplicated_total` | Counter | Alerts dropped as duplicates | Sudden spike may indicate alert loop |
| `soc_agent_alert_queue_depth` | Gauge | Current number of alerts waiting in the Celery queue | >5,000 = warning, >10,000 = critical |
| `soc_agent_alert_processing_latency_seconds` | Histogram | Time from ingestion to processing completion | p99 >60s = warning |
| `soc_agent_alerts_by_severity` | Counter | Alerts broken down by severity label | N/A (informational) |

#### Enrichment

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|----------------|
| `soc_agent_enrichment_requests_total` | Counter | Total enrichment API requests (labeled by source) | N/A |
| `soc_agent_enrichment_success_total` | Counter | Successful enrichment responses | N/A |
| `soc_agent_enrichment_errors_total` | Counter | Failed enrichment requests | >10/min = warning |
| `soc_agent_enrichment_rate_limited_total` | Counter | Requests rejected due to rate limits | >0 sustained = warning |
| `soc_agent_enrichment_cache_hit_total` | Counter | Cache hits for enrichment lookups | Low hit rate = cache misconfiguration |
| `soc_agent_enrichment_latency_seconds` | Histogram | Enrichment request duration | p99 >5s = investigate |

#### SIEM Connectivity

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|----------------|
| `soc_agent_siem_connected` | Gauge | 1 = connected, 0 = disconnected (labeled by SIEM type) | 0 for >5 min = critical |
| `soc_agent_siem_poll_success_total` | Counter | Successful SIEM poll cycles | Flatline = connector issue |
| `soc_agent_siem_poll_errors_total` | Counter | Failed SIEM poll attempts | >5 consecutive = critical |
| `soc_agent_siem_poll_latency_seconds` | Histogram | Time to complete a SIEM poll cycle | p99 >30s = investigate |

#### API Performance

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|----------------|
| `soc_agent_http_requests_total` | Counter | Total HTTP requests (labeled by method, path, status) | N/A |
| `soc_agent_http_request_duration_seconds` | Histogram | Request processing time | p99 >5s = warning |
| `soc_agent_http_requests_in_progress` | Gauge | Currently processing requests | >100 sustained = capacity issue |

#### Database

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|----------------|
| `soc_agent_db_pool_size` | Gauge | Configured pool size | N/A (informational) |
| `soc_agent_db_pool_checked_out` | Gauge | Currently in-use connections | >80% of pool = warning |
| `soc_agent_db_pool_available` | Gauge | Available connections in pool | 0 = critical |
| `soc_agent_db_query_duration_seconds` | Histogram | Query execution time | p99 >2s = investigate |

#### System

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|----------------|
| `process_resident_memory_bytes` | Gauge | Process memory usage | >80% of limit = warning |
| `process_cpu_seconds_total` | Counter | CPU time consumed | N/A |
| `python_gc_objects_collected_total` | Counter | Garbage collector activity | Rapid increase = memory pressure |

---

## 2. Grafana Dashboard Setup

### 2.1 Dashboard Panels

The pre-built Grafana dashboard (`infrastructure/grafana/soc-agent-dashboard.json`) includes these panels:

**Row 1: Overview**
- Alert ingestion rate (alerts/minute over time)
- Alert processing rate (alerts/minute over time)
- Current queue depth (single stat)
- SIEM connectivity status (traffic lights)
- Active incidents count (single stat)

**Row 2: Alert Processing**
- Processing latency histogram (p50, p90, p99)
- Alerts by severity (stacked bar chart)
- Alerts by SIEM source (pie chart)
- Deduplication rate (percentage)

**Row 3: Enrichment**
- Enrichment requests per source (stacked area)
- Enrichment latency by source (histogram)
- Rate limit events (bar chart)
- Cache hit rate (gauge)

**Row 4: API Performance**
- Request rate by status code (stacked area)
- Request latency (p50, p90, p99)
- Error rate percentage (gauge with threshold colors)
- Active connections (time series)

**Row 5: Infrastructure**
- CPU usage by pod (time series)
- Memory usage by pod (time series)
- Database connection pool utilization (gauge)
- Pod restart count (bar chart)

### 2.2 Dashboard Variables

| Variable | Query | Description |
|----------|-------|-------------|
| `namespace` | `label_values(kube_pod_info, namespace)` | Kubernetes namespace filter |
| `pod` | `label_values(kube_pod_info{namespace="$namespace"}, pod)` | Individual pod filter |
| `siem_type` | `label_values(soc_agent_siem_connected, siem_type)` | SIEM source filter |
| `interval` | `1m, 5m, 15m, 1h` | Aggregation interval |

### 2.3 Import Dashboard

```bash
# Option 1: Grafana API
curl -X POST "https://grafana.company.com/api/dashboards/db" \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dashboard": '"$(cat infrastructure/grafana/soc-agent-dashboard.json)"',
    "overwrite": true,
    "folderId": 0
  }'

# Option 2: Grafana ConfigMap (for Grafana provisioned via Helm)
kubectl create configmap soc-agent-grafana-dashboard \
  -n monitoring \
  --from-file=soc-agent.json=infrastructure/grafana/soc-agent-dashboard.json

kubectl label configmap soc-agent-grafana-dashboard \
  -n monitoring \
  grafana_dashboard=1
```

---

## 3. AlertManager Rules

### 3.1 Critical Alerts (Page Immediately)

```yaml
groups:
  - name: soc-agent-critical
    rules:
      - alert: SOCAgentDown
        expr: up{job="soc-agent-api"} == 0
        for: 2m
        labels:
          severity: critical
          team: soc-platform
        annotations:
          summary: "SOC Analyst Agent API is down"
          description: "No healthy API pods are responding to Prometheus scrapes."
          runbook_url: "https://docs.company.com/soc-agent/runbooks#agent-not-responding"

      - alert: SOCAgentSIEMDisconnected
        expr: soc_agent_siem_connected == 0
        for: 5m
        labels:
          severity: critical
          team: soc-platform
        annotations:
          summary: "SIEM connection lost ({{ $labels.siem_type }})"
          description: "The {{ $labels.siem_type }} SIEM connector has been disconnected for more than 5 minutes. Alert ingestion is halted for this source."
          runbook_url: "https://docs.company.com/soc-agent/runbooks#siem-connection-failure"

      - alert: SOCAgentDatabaseDown
        expr: soc_agent_db_pool_available == 0 and soc_agent_db_pool_checked_out == 0
        for: 1m
        labels:
          severity: critical
          team: soc-platform
        annotations:
          summary: "SOC Agent cannot connect to database"
          description: "All database connections are failing. The API will return 503 errors."
          runbook_url: "https://docs.company.com/soc-agent/runbooks#database-connection-pool"

      - alert: SOCAgentHighErrorRate
        expr: |
          (
            rate(soc_agent_http_requests_total{status=~"5.."}[5m])
            / rate(soc_agent_http_requests_total[5m])
          ) > 0.10
        for: 5m
        labels:
          severity: critical
          team: soc-platform
        annotations:
          summary: "SOC Agent API error rate above 10%"
          description: "{{ $value | humanizePercentage }} of requests are returning 5xx errors."
```

### 3.2 Warning Alerts (Investigate Within 30 Minutes)

```yaml
  - name: soc-agent-warning
    rules:
      - alert: SOCAgentHighAlertBacklog
        expr: soc_agent_alert_queue_depth > 5000
        for: 10m
        labels:
          severity: warning
          team: soc-platform
        annotations:
          summary: "Alert queue backlog is {{ $value }}"
          description: "Alert processing is falling behind. Check worker capacity and enrichment rate limits."
          runbook_url: "https://docs.company.com/soc-agent/runbooks#high-alert-backlog"

      - alert: SOCAgentEnrichmentRateLimited
        expr: rate(soc_agent_enrichment_rate_limited_total[5m]) > 0
        for: 15m
        labels:
          severity: warning
          team: soc-platform
        annotations:
          summary: "Enrichment API rate limited ({{ $labels.source }})"
          description: "{{ $labels.source }} enrichment is being rate limited. Alerts will have incomplete enrichment data."
          runbook_url: "https://docs.company.com/soc-agent/runbooks#ioc-enrichment-rate-limited"

      - alert: SOCAgentHighMemoryUsage
        expr: |
          container_memory_working_set_bytes{namespace="soc-agent"}
          / container_spec_memory_limit_bytes{namespace="soc-agent"} > 0.85
        for: 10m
        labels:
          severity: warning
          team: soc-platform
        annotations:
          summary: "Pod {{ $labels.pod }} memory usage above 85%"
          description: "Memory usage is {{ $value | humanizePercentage }}. OOMKill risk is elevated."
          runbook_url: "https://docs.company.com/soc-agent/runbooks#out-of-memory"

      - alert: SOCAgentPodRestarting
        expr: increase(kube_pod_container_status_restarts_total{namespace="soc-agent"}[1h]) > 3
        labels:
          severity: warning
          team: soc-platform
        annotations:
          summary: "Pod {{ $labels.pod }} restarted {{ $value }} times in 1 hour"
          description: "Frequent restarts indicate a crash loop or OOM condition."

      - alert: SOCAgentDatabasePoolNearExhaustion
        expr: soc_agent_db_pool_available / soc_agent_db_pool_size < 0.2
        for: 5m
        labels:
          severity: warning
          team: soc-platform
        annotations:
          summary: "Database connection pool below 20% available"
          description: "Only {{ $value | humanizePercentage }} of connections are available."
          runbook_url: "https://docs.company.com/soc-agent/runbooks#database-connection-pool"
```

---

## 4. PagerDuty Integration

### 4.1 Service Configuration

Create a PagerDuty service for SOC Agent platform alerts:

1. Navigate to PagerDuty > Services > New Service
2. Name: `SOC Analyst Agent - Platform`
3. Escalation Policy: SOC Platform Engineering on-call
4. Integration: Events API v2
5. Copy the Integration Key

### 4.2 AlertManager Configuration

```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m

route:
  receiver: default
  group_by: [alertname, namespace]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - match:
        severity: critical
        team: soc-platform
      receiver: soc-platform-pagerduty-critical
      group_wait: 10s
      repeat_interval: 1h
    - match:
        severity: warning
        team: soc-platform
      receiver: soc-platform-pagerduty-warning
      repeat_interval: 4h

receivers:
  - name: default
    webhook_configs: []

  - name: soc-platform-pagerduty-critical
    pagerduty_configs:
      - service_key: "PD_INTEGRATION_KEY"
        severity: critical
        description: '{{ .CommonAnnotations.summary }}'
        details:
          description: '{{ .CommonAnnotations.description }}'
          runbook: '{{ .CommonAnnotations.runbook_url }}'
          namespace: '{{ .CommonLabels.namespace }}'
          alertname: '{{ .CommonLabels.alertname }}'

  - name: soc-platform-pagerduty-warning
    pagerduty_configs:
      - service_key: "PD_INTEGRATION_KEY"
        severity: warning
        description: '{{ .CommonAnnotations.summary }}'
        details:
          description: '{{ .CommonAnnotations.description }}'
          runbook: '{{ .CommonAnnotations.runbook_url }}'
```

---

## 5. On-Call Procedures

### 5.1 On-Call Rotation

- **Team:** SOC Platform Engineering
- **Rotation:** Weekly, Monday 09:00 UTC to Monday 09:00 UTC
- **Primary on-call:** Responds to all critical alerts within 15 minutes
- **Secondary on-call:** Backup if primary does not acknowledge within 15 minutes
- **Escalation:** If no acknowledgment in 30 minutes, escalate to engineering manager

### 5.2 Incident Response Flow

1. **Alert fires** -- PagerDuty notification received
2. **Acknowledge** -- Within 15 minutes of page
3. **Assess** -- Check Grafana dashboard and relevant runbook
4. **Communicate** -- Post status in #soc-platform-incidents Slack channel
5. **Resolve** -- Follow runbook resolution steps
6. **Verify** -- Confirm metrics return to normal
7. **Close** -- Resolve PagerDuty incident, post summary in Slack
8. **Post-mortem** -- For critical incidents lasting >30 minutes, schedule a post-mortem within 3 business days

### 5.3 Severity Definitions

| Severity | Response Time | Examples |
|----------|--------------|---------|
| Critical | 15 minutes | Agent down, SIEM disconnected, database down, >10% error rate |
| Warning | 30 minutes | High backlog, rate limiting, high memory, pod restarts |
| Informational | Next business day | Configuration drift, approaching quota limits |

### 5.4 Communication Channels

| Channel | Purpose |
|---------|---------|
| PagerDuty | Alert notification and incident tracking |
| #soc-platform-incidents (Slack) | Real-time incident communication |
| #soc-platform-alerts (Slack) | Automated alert notifications (low severity) |
| Confluence / Wiki | Post-mortem reports and action items |
