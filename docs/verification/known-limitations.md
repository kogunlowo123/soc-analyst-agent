# Known Limitations

**Last Updated:** 2026-06-28
**Version:** 1.0

This document describes known performance, capacity, and functional limitations of the SOC Analyst Agent. Each limitation includes its impact, the conditions that trigger it, and recommended mitigations.

---

## 1. Alert Throughput Ceiling

**Limitation:** Maximum sustained throughput is 1,000 alerts per minute (approximately 16.7 alerts per second).

**Conditions:** This limit applies to the full processing pipeline: ingestion from SIEM, deduplication, enrichment, MITRE ATT&CK mapping, correlation, and persistence to PostgreSQL.

**Impact:** Alerts exceeding this rate will queue in Celery/Redis and be processed with increased latency. If the backlog grows beyond the Redis memory limit, alerts may be dropped.

**Root Cause:** The bottleneck is the synchronous IOC enrichment step. Each alert with new IOCs requires 1-3 external API calls (VirusTotal, AbuseIPDB, MISP), each taking 200-500ms.

**Mitigation:**
- Scale the Celery worker pod count horizontally (HPA is configured by default)
- Enable enrichment result caching in Redis (default TTL: 1 hour)
- Configure enrichment batching: group IOCs and query in bulk where APIs support it
- For burst scenarios, increase Redis `maxmemory` and set `maxmemory-policy` to `allkeys-lru`
- Monitor the `soc_agent_alert_queue_depth` Prometheus metric and alert when it exceeds 5,000

---

## 2. IOC Enrichment Rate Limits

**Limitation:** IOC enrichment is rate-limited by external threat intelligence API quotas.

| Service | Free Tier | Premium Tier | Effective Limit |
|---------|-----------|-------------|----------------|
| VirusTotal | 4 req/min, 500 req/day | 30,000 req/day | ~20 req/min sustained |
| AbuseIPDB | 1,000 checks/day | 50,000 checks/day | ~35 req/min sustained |
| MISP | No external limit | No external limit | Self-hosted capacity |
| CrowdStrike | 100 req/min per endpoint | 100 req/min per endpoint | 100 req/min |

**Impact:** When rate limits are reached, enrichment requests are queued with exponential backoff. Alerts are still processed but with partial enrichment data. Enrichment fields will show `pending` or `rate_limited` status.

**Mitigation:**
- Use premium API tiers for production deployments
- Enable aggressive caching: enrichment results for the same IOC are cached for 1 hour (IP/domain) or 24 hours (file hash)
- Prioritize enrichment: high-severity alerts are enriched first
- Monitor `soc_agent_enrichment_rate_limited_total` counter in Prometheus

---

## 3. MITRE ATT&CK Mapping Confidence

**Limitation:** Automatic MITRE ATT&CK technique mapping varies in confidence depending on the alert type and SIEM detection rule metadata.

| Alert Source | Mapping Confidence | Notes |
|-------------|-------------------|-------|
| SIEM rules with explicit MITRE tags | High (95%+) | Direct mapping from rule metadata |
| SIEM rules without MITRE tags | Medium (60-80%) | NLP-based inference from rule name and description |
| Raw alerts with minimal context | Low (30-50%) | Keyword matching against technique descriptions |
| Custom/proprietary detection rules | Variable | Depends on rule naming conventions |

**Impact:** ATT&CK coverage dashboards and technique heatmaps may show inaccurate mappings. Low-confidence mappings are flagged with a confidence score but may mislead analysts if not reviewed.

**Mitigation:**
- Configure MITRE ATT&CK tags directly in SIEM detection rules where possible
- Review and override low-confidence mappings via the agent dashboard
- Use the `MITRE_MAPPING_MIN_CONFIDENCE` environment variable to filter out mappings below a threshold (default: 0.5)
- Export mapping overrides to a JSON file for version control and team review

---

## 4. Large Log Query Timeouts

**Limitation:** SIEM queries scanning more than 1 million events may timeout.

| SIEM | Default Timeout | Max Events per Query | Notes |
|------|----------------|---------------------|-------|
| Splunk | 60 seconds | 50,000 (default `maxresultrows`) | Increase via `max_count` parameter |
| Elastic | 30 seconds | 10,000 (default `size`) | Use scroll API or PIT for larger sets |
| Sentinel | 180 seconds (KQL) | 500,000 rows | Hard limit on Log Analytics API |

**Impact:** Investigation queries spanning large time ranges or high-volume indexes may return partial results or fail entirely. The agent will log timeout errors and retry with a narrower time window.

**Mitigation:**
- The agent automatically splits large queries into 1-hour time windows and aggregates results
- Configure `SIEM_QUERY_TIMEOUT_SECONDS` to increase timeout (default: 60)
- For Splunk, use scheduled searches for recurring large queries
- For Elastic, the agent uses the Point-in-Time (PIT) API for queries exceeding 10,000 results
- For Sentinel, break queries into daily segments using `TimeGenerated` filters

---

## 5. Correlation Window

**Limitation:** Alert correlation is performed within a configurable time window (default: 24 hours). Attacks spanning longer periods may not be automatically correlated into a single incident.

**Impact:** A slow-and-low attack occurring over days or weeks will generate multiple separate incidents rather than one correlated incident.

**Mitigation:**
- Increase `CORRELATION_WINDOW_HOURS` (default: 24, max recommended: 168 / 7 days)
- Increasing the window increases memory usage and query latency proportionally
- Use manual incident linking in the dashboard for long-duration investigations
- Monitor `soc_agent_correlation_window_events` gauge to ensure the window is not overwhelming memory

---

## 6. Dashboard Concurrent Users

**Limitation:** The dashboard is designed for SOC team usage, not enterprise-wide access. Recommended maximum concurrent users: 50.

**Impact:** Beyond 50 concurrent WebSocket connections, dashboard updates may lag. API response times increase due to query contention on PostgreSQL.

**Mitigation:**
- Deploy additional API server replicas (HPA handles this automatically)
- Configure PostgreSQL connection pooling via PgBouncer (included in Helm chart)
- Use read replicas for dashboard queries if available
- Rate-limit dashboard API calls to 30 requests per second per user

---

## 7. Single SIEM Type per Connector Instance

**Limitation:** Each SIEM connector instance connects to one SIEM platform. To ingest alerts from multiple SIEM platforms simultaneously, multiple connector instances must be deployed.

**Impact:** Organizations using both Splunk and Elastic Security must run two connector pods with separate configurations.

**Mitigation:**
- The Helm chart supports deploying multiple SIEM connectors via the `siem.connectors` array in `values.yaml`
- Each connector is independently scalable
- Alert deduplication operates across all connectors, preventing duplicate processing when the same alert appears in multiple SIEMs

---

## 8. PostgreSQL Storage Growth

**Limitation:** Alert data, investigation history, and audit logs accumulate in PostgreSQL without automatic pruning unless retention is configured.

**Estimated Growth Rates:**

| Data Type | Per Alert | 1K alerts/day | 10K alerts/day |
|-----------|----------|---------------|----------------|
| Alert records | ~2 KB | ~60 MB/month | ~600 MB/month |
| Enrichment cache | ~1 KB | ~30 MB/month | ~300 MB/month |
| Investigation notes | ~5 KB | ~150 MB/month | ~1.5 GB/month |
| Audit logs | ~0.5 KB | ~15 MB/month | ~150 MB/month |

**Mitigation:**
- Set `ALERT_RETENTION_DAYS` environment variable (default: 365)
- A daily Celery beat task purges records older than the retention period
- Archive old data to S3/Blob Storage before purging using the export API
- Monitor PostgreSQL disk usage via `pg_database_size()` and alert at 80% capacity

---

## 9. No Offline Mode

**Limitation:** The agent requires continuous network connectivity to SIEM APIs and threat intelligence services. There is no offline or disconnected operation mode.

**Impact:** Network outages to external services degrade agent functionality. SIEM connectivity loss halts alert ingestion entirely.

**Mitigation:**
- The agent implements circuit breakers for all external API calls
- Failed enrichment calls are retried with exponential backoff (max 3 retries)
- Alerts received during TI API outages are processed without enrichment and flagged for re-enrichment when connectivity is restored
- SIEM connectivity is retried every 30 seconds with alerting after 5 consecutive failures

---

## 10. Limited Natural Language Processing

**Limitation:** The agent's NLP capabilities for alert triage and MITRE mapping are based on keyword matching and lightweight text classification, not large language models. Complex or ambiguous alert descriptions may be misclassified.

**Impact:** Alert priority scoring and MITRE technique mapping may be inaccurate for alerts with vague or non-standard descriptions.

**Mitigation:**
- Analysts can override priority and MITRE mappings via the dashboard
- Overrides are stored and used to improve future classification via feedback loop
- Configure `NLP_MODEL_TYPE` to use a more sophisticated model if compute resources allow (options: `keyword`, `tfidf`, `transformer`)

---

## 11. CrowdStrike Containment Latency

**Limitation:** Host containment actions via CrowdStrike Falcon API have an inherent latency of 30-120 seconds between API call and actual endpoint isolation, depending on the Falcon sensor's check-in interval.

**Impact:** During the containment latency window, a compromised endpoint may continue to communicate with command-and-control infrastructure.

**Mitigation:**
- This is a CrowdStrike platform limitation, not an agent limitation
- Configure Falcon sensors with reduced check-in intervals for critical assets
- The agent polls containment status every 15 seconds and updates the incident timeline when containment is confirmed

---

## 12. Timezone Handling

**Limitation:** All timestamps are stored and displayed in UTC. The dashboard does not support per-user timezone configuration.

**Impact:** Analysts in non-UTC timezones must mentally convert timestamps. Alert correlation across sources with inconsistent timezone handling in SIEM may produce incorrect timelines.

**Mitigation:**
- Ensure all SIEM sources normalize timestamps to UTC before ingestion
- Browser-based timezone conversion is planned for a future dashboard release
- API responses include `timezone: "UTC"` field for programmatic consumers
