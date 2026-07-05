# Monitoring Architecture

## Overview

The SOC Analyst Agent monitoring stack provides full observability across the application, infrastructure, and business metrics layers. Prometheus scrapes metrics from all application containers, Grafana renders operational dashboards, AlertManager routes alerts to PagerDuty and Slack, and Fluent Bit forwards structured logs to OpenSearch for centralized log analysis.

## Monitoring Stack Diagram

```mermaid
graph TB
    subgraph Applications["Application Containers (soc-agent namespace)"]
        api_metrics["FastAPI API<br/>/metrics (Port 8000)<br/>prometheus_fastapi_instrumentator<br/>Request latency, status codes,<br/>active connections"]
        engine_metrics["Agent Engine<br/>/metrics (Port 50051)<br/>prometheus_client<br/>Investigation duration,<br/>LLM token usage, tool calls"]
        worker_metrics["Celery Workers<br/>/metrics (Port 9808)<br/>celery-exporter<br/>Task execution time,<br/>queue depth, failure rate"]
        rag_metrics["RAG Pipeline<br/>/metrics (Port 8001)<br/>prometheus_client<br/>Retrieval latency,<br/>embedding throughput"]
        mcp_metrics["MCP Server<br/>/metrics (Port 8002)<br/>prometheus_client<br/>Tool call latency,<br/>external API errors"]
        dashboard_metrics["Next.js Dashboard<br/>Web Vitals<br/>LCP, INP, CLS"]
    end

    subgraph Prometheus_Stack["Prometheus Stack (monitoring namespace)"]
        prometheus["Prometheus Server<br/>v2.48<br/>Port: 9090<br/>Scrape interval: 15s<br/>Retention: 15 days<br/>Storage: 50 GB PVC"]
        alertmanager["AlertManager<br/>v0.27<br/>Port: 9093<br/>Dedup: 5 min<br/>Group wait: 30s<br/>Group interval: 5 min"]
        node_exporter["Node Exporter<br/>DaemonSet<br/>Port: 9100<br/>CPU, memory, disk, network"]
        kube_state["kube-state-metrics<br/>v2.10<br/>Port: 8080<br/>Pod, deployment, node state"]
        pushgateway["Pushgateway<br/>Port: 9091<br/>Batch job metrics<br/>Celery Beat tasks"]
    end

    subgraph Grafana_Stack["Grafana (monitoring namespace)"]
        grafana["Grafana Server<br/>v10.2<br/>Port: 3000<br/>SSO via Okta OIDC<br/>PostgreSQL backend"]

        subgraph Dashboards["SOC Dashboards"]
            dash_ops["SOC Operations<br/>Alert volume, triage rate,<br/>severity distribution,<br/>MTTA, MTTD, MTTR"]
            dash_agent["Agent Performance<br/>Investigation duration,<br/>LLM token usage/cost,<br/>tool call success rate,<br/>RAG retrieval quality"]
            dash_infra["Infrastructure<br/>CPU/memory utilization,<br/>pod health, node status,<br/>network I/O, disk usage"]
            dash_siem["SIEM Integration<br/>Alert ingestion rate,<br/>webhook failures,<br/>SIEM query latency,<br/>enrichment cache hit ratio"]
            dash_sla["SLA Tracking<br/>P1 response time (15 min SLA),<br/>P2 response time (1 hr SLA),<br/>escalation compliance,<br/>auto-close accuracy"]
        end
    end

    subgraph Logging_Stack["Logging Stack (logging namespace)"]
        fluentbit["Fluent Bit<br/>DaemonSet<br/>v2.2<br/>Collect stdout/stderr<br/>Kubernetes metadata<br/>JSON parsing"]
        opensearch_logs["OpenSearch<br/>Port: 9200<br/>Index: logs-soc-agent-*<br/>Retention: 30 days<br/>Daily rollover"]
        opensearch_dash["OpenSearch Dashboards<br/>Port: 5601<br/>Log exploration<br/>Saved searches<br/>Alert correlation"]
    end

    subgraph Alerting["Alert Routing"]
        pagerduty_int["PagerDuty<br/>Events API v2<br/>SOC Critical Service<br/>On-call escalation"]
        slack_alert["Slack<br/>#soc-monitoring<br/>Warning + Info alerts"]
        email_alert["Email<br/>SOC team DL<br/>Daily digest"]
    end

    subgraph External_Monitoring["External Monitoring"]
        uptime_robot["UptimeRobot<br/>External health checks<br/>every 60 seconds<br/>soc.example.com/health"]
        aws_cloudwatch["AWS CloudWatch<br/>RDS metrics<br/>ElastiCache metrics<br/>EKS control plane<br/>ALB metrics"]
    end

    api_metrics -->|Scrape /metrics| prometheus
    engine_metrics -->|Scrape /metrics| prometheus
    worker_metrics -->|Scrape /metrics| prometheus
    rag_metrics -->|Scrape /metrics| prometheus
    mcp_metrics -->|Scrape /metrics| prometheus
    node_exporter -->|Scrape /metrics| prometheus
    kube_state -->|Scrape /metrics| prometheus
    pushgateway -->|Scrape /metrics| prometheus
    aws_cloudwatch -->|CloudWatch Exporter| prometheus

    prometheus -->|PromQL queries| grafana
    prometheus -->|Alert rules eval| alertmanager

    alertmanager -->|Critical (P1)| pagerduty_int
    alertmanager -->|Warning (P2-P3)| slack_alert
    alertmanager -->|Info digest| email_alert

    grafana --> dash_ops
    grafana --> dash_agent
    grafana --> dash_infra
    grafana --> dash_siem
    grafana --> dash_sla

    api_metrics -->|stdout JSON logs| fluentbit
    engine_metrics -->|stdout JSON logs| fluentbit
    worker_metrics -->|stdout JSON logs| fluentbit
    fluentbit -->|HTTP bulk API| opensearch_logs
    opensearch_logs --> opensearch_dash

    style Applications fill:#e8f5e9,stroke:#388e3c
    style Prometheus_Stack fill:#fff3e0,stroke:#f57c00
    style Grafana_Stack fill:#e3f2fd,stroke:#1565c0
    style Logging_Stack fill:#f3e5f5,stroke:#7b1fa2
    style Alerting fill:#fce4ec,stroke:#c62828
    style External_Monitoring fill:#e0f7fa,stroke:#00838f
```

## Application Metrics

### FastAPI API Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `http_requests_total` | Counter | `method`, `endpoint`, `status_code` | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | `method`, `endpoint` | Request duration (buckets: 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10) |
| `http_requests_in_progress` | Gauge | - | Currently active requests |
| `websocket_connections_active` | Gauge | - | Active WebSocket connections |
| `alert_ingestion_total` | Counter | `source`, `status` | Alerts ingested by SIEM source |
| `alert_ingestion_duration_seconds` | Histogram | `source` | Time to process ingested alert |

### Agent Engine Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `investigation_duration_seconds` | Histogram | `severity`, `alert_type` | End-to-end investigation time |
| `triage_duration_seconds` | Histogram | `alert_type` | Alert classification time |
| `llm_tokens_used_total` | Counter | `model`, `direction` (input/output) | LLM token consumption |
| `llm_request_duration_seconds` | Histogram | `model`, `tool` | LLM API call duration |
| `llm_errors_total` | Counter | `model`, `error_type` | LLM API errors (rate limit, timeout, etc.) |
| `tool_calls_total` | Counter | `tool_name`, `status` | MCP tool invocations |
| `tool_call_duration_seconds` | Histogram | `tool_name` | Tool execution time |
| `ioc_enrichment_cache_hits_total` | Counter | `ioc_type` | Redis cache hits for IOC enrichment |
| `ioc_enrichment_cache_misses_total` | Counter | `ioc_type` | Redis cache misses |
| `correlation_cluster_size` | Histogram | - | Number of alerts per incident cluster |
| `mitre_techniques_mapped_total` | Counter | `tactic`, `confidence` | MITRE technique mappings |
| `severity_reassessments_total` | Counter | `direction` (upgrade/downgrade) | Severity changes after enrichment |

### Celery Worker Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `celery_tasks_total` | Counter | `task_name`, `status` | Task execution count |
| `celery_task_duration_seconds` | Histogram | `task_name` | Task execution time |
| `celery_queue_length` | Gauge | `queue_name` | Current queue depth |
| `celery_active_workers` | Gauge | `queue_name` | Active worker count |
| `celery_task_retries_total` | Counter | `task_name` | Task retry count |

## AlertManager Rules

### Critical Alerts (Page via PagerDuty)

```yaml
groups:
  - name: soc-agent-critical
    rules:
      - alert: HighAlertIngestionFailureRate
        expr: rate(alert_ingestion_total{status="error"}[5m]) / rate(alert_ingestion_total[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
          service: soc-agent
        annotations:
          summary: "Alert ingestion failure rate above 10%"
          description: "{{ $value | humanizePercentage }} of alerts failing ingestion from {{ $labels.source }}"
          runbook: "https://wiki.internal/runbooks/soc-agent/alert-ingestion-failure"

      - alert: AgentEngineDown
        expr: up{job="agent-engine"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Agent Engine is down"
          description: "No agent-engine instances responding to health checks for 2 minutes"

      - alert: LLMAPIErrorRateHigh
        expr: rate(llm_errors_total[5m]) > 5
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "LLM API error rate exceeds 5 errors/min"
          description: "Model {{ $labels.model }} experiencing {{ $value }} errors/min"

      - alert: P1AlertSLABreach
        expr: histogram_quantile(0.95, rate(investigation_duration_seconds_bucket{severity="critical"}[15m])) > 900
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "P1 alert investigation SLA breach (15 min)"
          description: "95th percentile investigation time for critical alerts: {{ $value | humanizeDuration }}"

      - alert: DatabaseConnectionPoolExhausted
        expr: pg_stat_activity_count / pg_settings_max_connections > 0.9
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "PostgreSQL connection pool at 90% capacity"
```

### Warning Alerts (Slack Notification)

```yaml
      - alert: HighEnrichmentLatency
        expr: histogram_quantile(0.95, rate(tool_call_duration_seconds_bucket{tool_name="enrich_ioc"}[15m])) > 15
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "IOC enrichment latency p95 above 15 seconds"

      - alert: CeleryQueueBacklog
        expr: celery_queue_length{queue_name="default"} > 500
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Celery default queue backlog exceeds 500 tasks"

      - alert: LowCacheHitRatio
        expr: rate(ioc_enrichment_cache_hits_total[1h]) / (rate(ioc_enrichment_cache_hits_total[1h]) + rate(ioc_enrichment_cache_misses_total[1h])) < 0.5
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "IOC enrichment cache hit ratio below 50%"

      - alert: HighMemoryUsage
        expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Container {{ $labels.container }} memory usage above 85%"

      - alert: PodRestartLoop
        expr: increase(kube_pod_container_status_restarts_total{namespace="soc-agent"}[1h]) > 3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Pod {{ $labels.pod }} restarting frequently ({{ $value }} restarts/hour)"
```

## Grafana Dashboard Panels

### SOC Operations Dashboard

| Panel | Visualization | Query | Purpose |
|-------|--------------|-------|---------|
| Alert Volume (24h) | Time series | `sum(rate(alert_ingestion_total[5m])) by (source)` | Alert ingestion rate by SIEM source |
| Severity Distribution | Pie chart | `sum(alert_ingestion_total) by (severity)` over 24h | Alert severity breakdown |
| Mean Time to Triage | Stat | `histogram_quantile(0.50, rate(triage_duration_seconds_bucket[1h]))` | Median triage time |
| Mean Time to Detect (MTTD) | Stat | Custom: alert timestamp - event timestamp (avg over 24h) | Detection speed |
| Investigation Duration (p95) | Gauge | `histogram_quantile(0.95, rate(investigation_duration_seconds_bucket[1h]))` | Investigation speed |
| Active Investigations | Stat | `count(investigations WHERE status = 'active')` | Open investigation count |
| Auto-Close Rate | Stat | `sum(alert_ingestion_total{status="auto_closed"}) / sum(alert_ingestion_total)` | Percentage of auto-closed alerts |
| Escalation Rate | Stat | `sum(alert_ingestion_total{action="escalate"}) / sum(alert_ingestion_total)` | Escalation percentage |

### Agent Performance Dashboard

| Panel | Visualization | Query | Purpose |
|-------|--------------|-------|---------|
| LLM Token Usage | Time series | `sum(rate(llm_tokens_used_total[5m])) by (model, direction)` | Token burn rate |
| Estimated LLM Cost | Stat | `sum(llm_tokens_used_total{direction="input"}) * 0.0000025 + sum(llm_tokens_used_total{direction="output"}) * 0.00001` | Dollar cost estimate |
| Tool Call Success Rate | Bar gauge | `sum(tool_calls_total{status="success"}) / sum(tool_calls_total) by (tool_name)` | Per-tool reliability |
| RAG Retrieval Latency (p95) | Time series | `histogram_quantile(0.95, rate(rag_retrieval_duration_seconds_bucket[5m]))` | Retrieval speed |
| Enrichment Cache Hit Ratio | Gauge | `sum(rate(ioc_enrichment_cache_hits_total[1h])) / (hits + misses)` | Cache effectiveness |
| MITRE Mapping Confidence | Histogram | Distribution of `mitre_techniques_mapped_total` by confidence bucket | Mapping quality |

## Structured Logging Format

All application logs are emitted as JSON to stdout and collected by Fluent Bit:

```json
{
  "timestamp": "2026-07-04T10:30:00.123Z",
  "level": "INFO",
  "logger": "soc_agent.api.alerts",
  "message": "Alert ingested successfully",
  "trace_id": "abc123def456",
  "span_id": "789ghi012",
  "alert_id": "alert_001",
  "source": "splunk",
  "severity": 85,
  "duration_ms": 245,
  "user_id": null,
  "request_id": "req_abc123",
  "pod_name": "fastapi-api-7b8c9d-x2k4f",
  "namespace": "soc-agent",
  "node_name": "ip-10-0-10-42.ec2.internal"
}
```

## Health Check Endpoints

| Endpoint | Port | Check | Failure Threshold |
|----------|------|-------|-------------------|
| `GET /health` | 8000 | Basic liveness (process running) | 3 consecutive failures -> restart |
| `GET /ready` | 8000 | Readiness (DB + Redis + OpenSearch connected) | 3 consecutive failures -> remove from LB |
| `GET /metrics` | 8000 | Prometheus metrics endpoint | N/A |
| `GET /health` | 8001 | RAG pipeline + OpenSearch connectivity | 3 failures -> restart |
| `GET /health` | 8002 | MCP server + external API reachability | 3 failures -> restart |
| `GET /health` | 8003 | A2A handler + peer agent registry | 3 failures -> restart |
