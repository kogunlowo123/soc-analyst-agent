# Frequently Asked Questions

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## Setup

### Q1: What are the minimum infrastructure requirements to run the SOC Analyst Agent?

The minimum requirements for a functional deployment:

- **Kubernetes:** 3 worker nodes, each with 4 vCPUs and 8 GB RAM (Kubernetes 1.28+)
- **PostgreSQL:** Single instance, 2 vCPUs, 4 GB RAM, 50 GB SSD storage (version 15 or 16)
- **Redis:** Single instance, 1 vCPU, 2 GB RAM (version 7.x)
- **At least one SIEM** accessible via API (Splunk, Elastic Security, or Microsoft Sentinel)
- **At least one TI API key** (VirusTotal free tier is sufficient for evaluation)

For production, double these resources and use managed database services with high availability.

### Q2: Can I run the agent without Kubernetes?

The agent is designed for Kubernetes deployment. However, it can run on Docker Compose for development and evaluation purposes. The `docker-compose.yml` in the repository root starts the API server, workers, connectors, PostgreSQL, and Redis as local containers. This is not recommended for production use because it lacks autoscaling, rolling updates, and pod health management.

### Q3: Which SIEMs are supported? Can I use more than one simultaneously?

Supported SIEMs: Splunk Enterprise/Cloud, Elastic Security (8.x), and Microsoft Sentinel. You can connect to multiple SIEMs simultaneously by configuring multiple connector instances. Each connector runs as an independent pod. Alert deduplication ensures that if the same alert appears in multiple SIEMs, it is processed only once.

### Q4: How do I add a new SIEM integration?

Add a new entry to the `siem.connectors` array in your Helm `values.yaml` file:

```yaml
siem:
  connectors:
    - type: splunk
      enabled: true
      pollIntervalSeconds: 30
    - type: elastic
      enabled: true
      pollIntervalSeconds: 30
```

Create the corresponding secrets for the new SIEM's credentials, then run `helm upgrade`.

### Q5: Do I need all threat intelligence APIs, or can I start with just one?

You can start with a single TI source. The agent degrades gracefully: if a TI source is not configured, enrichment for that source is simply skipped. For production, configure at least VirusTotal (for file hash and URL analysis) and AbuseIPDB (for IP reputation). MISP and CrowdStrike add depth but are not required for basic operation.

---

## Operations

### Q6: How many alerts per day can the agent handle?

The agent is tested for sustained throughput of 1,000 alerts per minute (approximately 1.44 million alerts per day). This throughput assumes:

- 4 Celery worker pods with default concurrency
- Enrichment caching enabled (1-hour TTL)
- Premium tier TI API keys
- PostgreSQL with sufficient connection pool capacity

For higher volumes, scale workers horizontally. The bottleneck is typically TI API rate limits, not the agent itself.

### Q7: How does the agent handle SIEM downtime?

When a SIEM becomes unreachable:

1. The connector logs a warning and retries every 30 seconds.
2. After 5 consecutive failures, a `SOCAgentSIEMDisconnected` critical alert fires.
3. Alerts from other connected SIEMs continue to be processed normally.
4. When the SIEM recovers, the connector resumes polling from the last successful checkpoint, so no alerts are permanently missed (assuming SIEM retention covers the gap).

### Q8: How do I tune false positive reduction?

The agent provides several mechanisms:

1. **Alert priority scoring:** Configure `PRIORITY_SCORING_MODEL` to adjust how alerts are scored. Low-confidence alerts can be auto-closed.
2. **Deduplication window:** Adjust `DEDUP_WINDOW_SECONDS` (default: 300) to merge duplicate alerts more aggressively.
3. **Allowlists:** Add known-safe IPs, domains, and hashes to the allowlist via the API. Alerts matching allowlisted IOCs are auto-closed as benign.
4. **SIEM rule tuning feedback:** The agent reports per-rule false positive rates. Use this data to tune SIEM detection rules at the source.

### Q9: Can the agent automatically isolate compromised endpoints?

Yes, but only with human approval. The agent can trigger CrowdStrike Falcon network containment, but it requires explicit approval from a user with the `soc_lead` or `admin` role. Fully automated containment without human approval is not supported by design to prevent business disruption from false positives.

### Q10: How do I back up the agent's data?

Back up PostgreSQL using your standard database backup procedures:

- **AWS RDS:** Automated snapshots (daily) and on-demand snapshots before upgrades
- **Azure Database:** Automated backups with point-in-time recovery
- **GCP Cloud SQL:** Automated backups with binary logging
- **Self-hosted:** `pg_dump` or continuous archiving with `pg_basebackup`

Redis data is ephemeral (cache and task queue) and does not need to be backed up. Alert data and investigation notes live in PostgreSQL.

---

## Security

### Q11: How are SIEM credentials stored?

SIEM credentials are stored in a secret manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager). They are injected into pods as environment variables at startup. Credentials are never written to disk inside the container, never logged, and never exposed through the API.

In development environments, credentials can be stored in Kubernetes Secrets as a fallback, but this is not recommended for production because Kubernetes Secrets are base64-encoded (not encrypted) by default.

### Q12: What happens if an API key is compromised?

1. **Revoke immediately:** Delete the compromised key via the API (`DELETE /api/v1/admin/api-keys/{key_id}`).
2. **Rotate SIEM/TI credentials:** Update the compromised credential in the secret manager and restart affected pods.
3. **Review audit logs:** Query the `audit_logs` table for any actions performed with the compromised credential since the suspected compromise date.
4. **Generate new keys:** Create new API keys or credentials for legitimate consumers.
5. **Investigate:** Determine how the key was compromised and remediate the root cause.

### Q13: Does the agent comply with SOC 2 / GDPR / HIPAA?

The agent provides operational security controls (encryption, RBAC, audit logging, secret management) that support compliance, but it does not generate compliance reports or enforce regulatory requirements. Compliance is the responsibility of the deploying organization. The agent's audit logs and access controls can serve as evidence for SOC 2 Type II audits. For GDPR, ensure that alert data containing PII is handled according to your data processing agreements, and configure `ALERT_RETENTION_DAYS` to align with your retention policy.

### Q14: How is data encrypted?

- **In transit:** TLS 1.3 for all external connections. mTLS between pods when a service mesh is deployed.
- **At rest:** AES-256-GCM encryption managed by the cloud provider's KMS for databases and object storage. Application-level AES-256-GCM encryption for sensitive fields (emails, SIEM credentials) in the database.
- **API keys:** Stored as SHA-256 hashes. The original key cannot be recovered from the hash.
- **JWT tokens:** Signed with RS256 (4096-bit RSA). The private key is stored in the secret manager.

---

## Scaling

### Q15: How do I scale the agent for higher alert volumes?

Horizontal scaling is the primary mechanism:

1. **API server pods:** Scale via HPA based on CPU utilization (default target: 70%). Increase `maxReplicas` in HPA configuration.
2. **Celery worker pods:** Scale via HPA based on CPU or custom metric (alert queue depth). This is the most common component to scale.
3. **SIEM connector pods:** Scale if connecting to multiple SIEM instances. Each connector handles one SIEM connection.
4. **PostgreSQL:** Use read replicas for dashboard queries. Increase connection pool size.
5. **Redis:** Increase `maxmemory`. Consider Redis Cluster for very high throughput.

Vertical scaling (larger pods) is a secondary option if horizontal scaling is not sufficient.

### Q16: What are the cost implications of running the agent?

Estimated monthly costs (AWS, us-east-1, on-demand pricing, moderate volume of 10,000 alerts/day):

| Component | Specification | Estimated Monthly Cost |
|-----------|--------------|----------------------|
| EKS Cluster | 3 x m6i.xlarge nodes | $350 |
| RDS PostgreSQL | db.r6g.large, Multi-AZ | $380 |
| ElastiCache Redis | cache.r6g.large, 1 replica | $290 |
| S3 Storage | 50 GB | $1 |
| Data Transfer | ~100 GB outbound | $9 |
| VirusTotal Premium | 30K req/day | $800/month (varies by plan) |
| AbuseIPDB Premium | 50K checks/day | $200/month (varies by plan) |
| **Total** | | **~$2,030/month** |

Costs decrease with reserved instances (30-40% savings) and increase with higher alert volumes or premium TI tiers.

### Q17: Can I deploy the agent in multiple regions for disaster recovery?

Yes. Deploy independent agent instances in each region, each connecting to the regional SIEM infrastructure. There is no built-in cross-region replication. For active-passive DR:

1. Maintain the Helm chart and configuration in version control.
2. In the DR region, keep the infrastructure provisioned but the agent scaled to zero replicas.
3. On failover, scale up the DR agent and point DNS to the DR ingress.
4. Database replication (cross-region read replicas) must be configured separately.

### Q18: How long does an upgrade take with zero downtime?

A typical rolling upgrade completes in 3-5 minutes with zero downtime:

1. Helm triggers a rolling update of each Deployment.
2. New pods start and pass readiness probes before old pods are terminated.
3. PodDisruptionBudget ensures at least 2 API pods are always available.
4. Database migrations (if any) run before the application update via a pre-upgrade Job.

The only scenario requiring brief downtime is a breaking database migration that is incompatible with the previous application version. This is noted in release notes when it occurs.
