# Operational Runbooks

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## Runbook 1: Agent Not Responding to Alerts

### Symptoms
- No new alerts appearing in the dashboard
- `soc_agent_alerts_processed_total` metric is flat (no increase)
- SOC analysts report stale data in the dashboard
- SIEM shows active alerts but the agent is not processing them

### Diagnosis Steps

1. **Check pod health:**
   ```bash
   kubectl get pods -n soc-agent -o wide
   kubectl get pods -n soc-agent | grep -v Running
   ```

2. **Check SIEM connector logs:**
   ```bash
   kubectl logs -n soc-agent -l component=connector --tail=100 | grep -E "ERROR|WARN"
   ```

3. **Check Celery worker status:**
   ```bash
   kubectl logs -n soc-agent -l component=worker --tail=100 | grep -E "ERROR|WARN"
   kubectl exec -n soc-agent deploy/soc-agent-worker -- celery -A app.worker inspect active
   ```

4. **Check Redis queue depth:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-api -- python -c "
   import redis
   r = redis.from_url('rediss://...')
   print('Queue length:', r.llen('celery'))
   "
   ```

5. **Check SIEM API connectivity:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-connector -- \
     curl -s -o /dev/null -w "%{http_code}" https://splunk.company.com:8089/services/server/info \
     -H "Authorization: Bearer $SPLUNK_TOKEN"
   ```

### Resolution Steps

| Finding | Resolution |
|---------|-----------|
| Connector pods are CrashLoopBackOff | Check logs for the crash reason. Common: SIEM credentials expired, network unreachable. Fix the root cause and the pod will restart automatically. |
| Celery workers are idle but queue is empty | SIEM connector is not fetching alerts. Restart connector: `kubectl rollout restart deployment/soc-agent-connector -n soc-agent` |
| Queue is full but workers are stuck | Workers may be deadlocked. Restart workers: `kubectl rollout restart deployment/soc-agent-worker -n soc-agent` |
| SIEM API returns 401 | Credentials have expired. Rotate credentials in secret manager and restart connector pods. |
| SIEM API returns timeout | SIEM is overloaded or network is congested. Check SIEM health. Increase `SIEM_QUERY_TIMEOUT_SECONDS`. |

### Escalation
If unresolved after 15 minutes, page the SOC Platform Engineering on-call via PagerDuty.

---

## Runbook 2: SIEM Connection Failure

### Symptoms
- Health endpoint shows `"siem_splunk": "disconnected"` (or equivalent for Elastic/Sentinel)
- `soc_agent_siem_connected` metric is 0
- AlertManager fires `SOCAgentSIEMDisconnected` alert
- Connector pod logs show repeated connection errors

### Diagnosis Steps

1. **Identify which SIEM is affected:**
   ```bash
   curl -s http://soc-agent-api.soc-agent.svc.cluster.local:8000/health | python -m json.tool
   ```

2. **Check connector pod logs:**
   ```bash
   kubectl logs -n soc-agent -l component=connector,siem=splunk --tail=50
   ```

3. **Test network connectivity from the pod:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-connector -- \
     curl -v --connect-timeout 5 https://splunk.company.com:8089/
   ```

4. **Check DNS resolution:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-connector -- \
     nslookup splunk.company.com
   ```

5. **Check for NetworkPolicy blocking traffic:**
   ```bash
   kubectl get networkpolicy -n soc-agent -o yaml
   ```

### Resolution Steps

| Finding | Resolution |
|---------|-----------|
| DNS resolution fails | Check CoreDNS pods: `kubectl get pods -n kube-system -l k8s-app=kube-dns`. Verify DNS ConfigMap. |
| Connection refused | SIEM API endpoint is down. Contact SIEM admin team. |
| TLS handshake error | Certificate on SIEM has changed or expired. Update CA bundle in the agent's trusted certificates. |
| 401 Unauthorized | SIEM credentials expired. Rotate in secret manager. Restart connector: `kubectl rollout restart deployment/soc-agent-connector -n soc-agent` |
| Connection timeout | Firewall rule change or VPN tunnel down. Check network path with the network team. |
| NetworkPolicy blocking | Update NetworkPolicy to allow egress to the SIEM endpoint IP and port. |

### Escalation
If the SIEM itself is down, escalate to the SIEM administration team. If it is a network issue, escalate to the network operations team.

---

## Runbook 3: High Alert Backlog

### Symptoms
- `soc_agent_alert_queue_depth` metric exceeds 5,000
- AlertManager fires `SOCAgentHighAlertBacklog` alert
- Alert processing latency exceeds 5 minutes (measured by `soc_agent_alert_processing_latency_seconds`)
- Dashboard shows alerts with significant delay

### Diagnosis Steps

1. **Check current queue depth:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-api -- \
     curl -s http://localhost:8000/metrics | grep soc_agent_alert_queue_depth
   ```

2. **Check worker capacity:**
   ```bash
   kubectl get hpa soc-agent-worker -n soc-agent
   kubectl top pods -n soc-agent -l component=worker
   ```

3. **Check for enrichment bottleneck:**
   ```bash
   kubectl logs -n soc-agent -l component=worker --tail=100 | grep "rate_limited"
   ```

4. **Check if alert volume spiked:**
   ```bash
   # Query Prometheus for alert ingestion rate
   # rate(soc_agent_alerts_ingested_total[5m])
   ```

### Resolution Steps

1. **Scale workers immediately:**
   ```bash
   kubectl scale deployment soc-agent-worker -n soc-agent --replicas=10
   ```

2. **If enrichment is the bottleneck, temporarily disable non-critical enrichment:**
   ```bash
   kubectl set env deployment/soc-agent-worker -n soc-agent \
     ENRICHMENT_SKIP_LOW_PRIORITY=true
   ```

3. **If alert volume is genuinely high (not a flood attack), increase HPA max:**
   ```bash
   kubectl patch hpa soc-agent-worker -n soc-agent \
     --type='json' -p='[{"op":"replace","path":"/spec/maxReplicas","value":30}]'
   ```

4. **If it is a flood of duplicate alerts, verify deduplication is working:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-api -- \
     curl -s http://localhost:8000/metrics | grep soc_agent_alerts_deduplicated_total
   ```

5. **Once backlog is cleared, reset scaling to normal values.**

### Escalation
If the backlog is caused by a genuine security incident generating thousands of alerts, notify the SOC lead immediately. The backlog itself may be evidence of an ongoing attack.

---

## Runbook 4: IOC Enrichment API Rate Limited

### Symptoms
- `soc_agent_enrichment_rate_limited_total` counter is increasing
- Alert enrichment data shows `status: rate_limited` for affected TI source
- Logs show `429 Too Many Requests` from VirusTotal or AbuseIPDB
- Dashboard enrichment panels show stale or missing data

### Diagnosis Steps

1. **Identify which TI source is rate limited:**
   ```bash
   kubectl logs -n soc-agent -l component=worker --tail=200 | grep "429"
   ```

2. **Check current enrichment request rate:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-api -- \
     curl -s http://localhost:8000/metrics | grep soc_agent_enrichment_requests_total
   ```

3. **Check cache hit rate:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-api -- \
     curl -s http://localhost:8000/metrics | grep soc_agent_enrichment_cache_hit
   ```

### Resolution Steps

1. **Verify caching is enabled and working:**
   - Check `ENRICHMENT_CACHE_TTL_SECONDS` is set (default: 3600)
   - Low cache hit rate suggests many unique IOCs; increase TTL if acceptable

2. **Reduce enrichment frequency for low-priority alerts:**
   ```bash
   kubectl set env deployment/soc-agent-worker -n soc-agent \
     ENRICHMENT_PRIORITY_THRESHOLD=medium
   ```

3. **If using free tier, upgrade to premium API tier.** This is the permanent fix for production deployments.

4. **Re-enrich rate-limited alerts once quota resets:**
   ```bash
   # Trigger re-enrichment of pending alerts
   kubectl exec -n soc-agent deploy/soc-agent-api -- \
     curl -X POST http://localhost:8000/api/v1/admin/enrichment/retry-pending \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

### Escalation
No escalation needed unless rate limiting is affecting investigation of an active incident. In that case, contact the TI provider for emergency quota increase.

---

## Runbook 5: Database Connection Pool Exhaustion

### Symptoms
- API returns 503 Service Unavailable
- `soc_agent_db_pool_available` metric is 0
- AlertManager fires `SOCAgentDatabaseConnectionPoolExhausted`
- Logs show `QueuePool limit of size 20 overflow 10 reached`

### Diagnosis Steps

1. **Check current connection pool status:**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-api -- \
     curl -s http://localhost:8000/metrics | grep soc_agent_db_pool
   ```

2. **Check PostgreSQL active connections:**
   ```bash
   kubectl run pg-check --rm -it --image=postgres:16-alpine --restart=Never -- \
     psql "$DATABASE_URL" -c "SELECT count(*) FROM pg_stat_activity WHERE datname='soc_analyst_agent';"
   ```

3. **Check for long-running queries:**
   ```bash
   kubectl run pg-check --rm -it --image=postgres:16-alpine --restart=Never -- \
     psql "$DATABASE_URL" -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query FROM pg_stat_activity WHERE datname='soc_analyst_agent' AND state != 'idle' ORDER BY duration DESC LIMIT 10;"
   ```

4. **Check if connection leaks exist:**
   ```bash
   kubectl logs -n soc-agent -l component=api --tail=200 | grep -i "connection"
   ```

### Resolution Steps

1. **Kill long-running queries if safe:**
   ```bash
   kubectl run pg-fix --rm -it --image=postgres:16-alpine --restart=Never -- \
     psql "$DATABASE_URL" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='soc_analyst_agent' AND state != 'idle' AND now() - query_start > interval '5 minutes';"
   ```

2. **Increase pool size temporarily:**
   ```bash
   kubectl set env deployment/soc-agent-api -n soc-agent \
     DATABASE_POOL_SIZE=40 DATABASE_MAX_OVERFLOW=20
   ```

3. **Deploy PgBouncer if not already in use:**
   PgBouncer acts as a connection multiplexer, allowing many application connections to share fewer database connections.

4. **Restart API pods to reset connections:**
   ```bash
   kubectl rollout restart deployment/soc-agent-api -n soc-agent
   ```

### Escalation
If PostgreSQL itself is the bottleneck (high CPU/memory), escalate to the database administration team.

---

## Runbook 6: Out of Memory (OOM)

### Symptoms
- Pods are being OOMKilled: `kubectl get pods -n soc-agent` shows `OOMKilled` in STATUS
- `kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}` fires
- Pod restart count is increasing

### Diagnosis Steps

1. **Identify which pod is OOMKilled:**
   ```bash
   kubectl get pods -n soc-agent -o json | \
     python -c "import sys,json; [print(c['name'], c['lastState']['terminated']['reason']) for p in json.load(sys.stdin)['items'] for c in p['status']['containerStatuses'] if c.get('lastState',{}).get('terminated',{}).get('reason') == 'OOMKilled']"
   ```

2. **Check memory usage before OOM:**
   ```bash
   kubectl top pods -n soc-agent --sort-by=memory
   ```

3. **Check if memory limits are too low:**
   ```bash
   kubectl get deployment soc-agent-api -n soc-agent -o jsonpath='{.spec.template.spec.containers[0].resources}'
   ```

4. **Check for memory leaks in application logs:**
   ```bash
   kubectl logs -n soc-agent deploy/soc-agent-api --previous --tail=50
   ```

### Resolution Steps

1. **Increase memory limits:**
   ```bash
   kubectl set resources deployment/soc-agent-api -n soc-agent \
     --limits=memory=4Gi --requests=memory=1Gi
   ```

2. **If the worker is OOMKilled, reduce concurrency:**
   ```bash
   kubectl set env deployment/soc-agent-worker -n soc-agent \
     CELERY_WORKER_CONCURRENCY=2
   ```

3. **If OOM is caused by large query results, add pagination:**
   Check `SIEM_QUERY_MAX_RESULTS` and reduce if needed.

4. **Monitor memory after fix:**
   ```bash
   kubectl top pods -n soc-agent -l component=api --no-headers | awk '{print $1, $3}'
   ```

### Escalation
If OOM persists after increasing limits to 4 GB, investigate for memory leaks. Engage the development team with a heap profile.

---

## Runbook 7: Certificate Expiration

### Symptoms
- Browser shows TLS certificate warning when accessing dashboard
- `curl` fails with `SSL certificate problem: certificate has expired`
- AlertManager fires certificate expiration warning (if configured)
- Logs show `SSLError` for outbound connections

### Diagnosis Steps

1. **Check ingress TLS certificate:**
   ```bash
   echo | openssl s_client -connect soc-agent.company.com:443 -servername soc-agent.company.com 2>/dev/null | openssl x509 -noout -dates
   ```

2. **Check cert-manager certificate status:**
   ```bash
   kubectl get certificate -n soc-agent
   kubectl describe certificate soc-agent-tls -n soc-agent
   ```

3. **Check if cert-manager is functioning:**
   ```bash
   kubectl get pods -n cert-manager
   kubectl logs -n cert-manager deploy/cert-manager --tail=50
   ```

4. **Check certificates used for outbound connections (SIEM, TI):**
   ```bash
   kubectl exec -n soc-agent deploy/soc-agent-connector -- \
     openssl s_client -connect splunk.company.com:8089 2>/dev/null | openssl x509 -noout -dates
   ```

### Resolution Steps

| Scenario | Resolution |
|----------|-----------|
| cert-manager renewal failed | Check CertificateRequest and Order resources. Fix ACME challenge issues. Force renewal: `kubectl delete certificate soc-agent-tls -n soc-agent` and let cert-manager recreate it. |
| cert-manager is not installed | Install cert-manager or manually provision a certificate and create the TLS secret: `kubectl create secret tls soc-agent-tls --cert=cert.pem --key=key.pem -n soc-agent` |
| SIEM/TI API certificate expired | This is on the SIEM/TI side. Contact the SIEM admin. As a temporary workaround, set `VERIFY_SSL=false` (not recommended for production). |
| CA bundle is outdated | Update the CA bundle in the agent pod's trusted certificates. |

### Escalation
If certificates are managed externally (not by cert-manager), escalate to the PKI or security team.
