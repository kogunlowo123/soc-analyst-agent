# Troubleshooting Guide

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## Log Analysis

### Accessing Logs

```bash
# All API server logs
kubectl logs -n soc-agent -l component=api --tail=100

# All worker logs
kubectl logs -n soc-agent -l component=worker --tail=100

# Connector logs for a specific SIEM
kubectl logs -n soc-agent -l component=connector,siem=splunk --tail=100

# Previous container logs (after a crash)
kubectl logs -n soc-agent POD_NAME --previous --tail=100

# Follow logs in real time
kubectl logs -n soc-agent -l component=api -f

# Filter for errors only (structured JSON logs)
kubectl logs -n soc-agent -l component=api --tail=500 | \
  python -c "import sys,json; [print(json.dumps(l)) for line in sys.stdin if (l:=json.loads(line)).get('level') in ('ERROR','CRITICAL')]"
```

### Log Patterns

| Pattern | Meaning | Action |
|---------|---------|--------|
| `"level":"ERROR","msg":"database connection failed"` | Cannot reach PostgreSQL | Check DB connectivity, credentials, SSL |
| `"level":"ERROR","msg":"redis connection refused"` | Cannot reach Redis | Check Redis host/port, password, TLS |
| `"level":"WARNING","msg":"enrichment rate limited"` | TI API quota reached | See Runbook 4 |
| `"level":"ERROR","msg":"siem poll failed"` | SIEM API error | Check SIEM credentials, network |
| `"level":"ERROR","msg":"jwt validation failed"` | Invalid or expired token | Check clock sync, key rotation |
| `"level":"ERROR","msg":"alembic migration failed"` | Schema migration error | Check migration user permissions |

### Debug Mode

Enable verbose logging for diagnosis (temporary only):

```bash
# Enable debug logging on API pods
kubectl set env deployment/soc-agent-api -n soc-agent APP_LOG_LEVEL=DEBUG

# Remember to revert after diagnosis
kubectl set env deployment/soc-agent-api -n soc-agent APP_LOG_LEVEL=INFO
```

---

## Common Issues

### Issue 1: Pods stuck in `Pending` state

**Symptoms:** `kubectl get pods` shows pods in `Pending` status.

**Diagnosis:**
```bash
kubectl describe pod POD_NAME -n soc-agent | grep -A 10 Events
```

**Causes and Resolutions:**

| Cause | Resolution |
|-------|-----------|
| Insufficient CPU/memory on nodes | Scale up the node group or reduce resource requests |
| No nodes match nodeSelector | Verify node labels match pod nodeSelector |
| PVC pending (no StorageClass) | Create a default StorageClass or specify one in the PVC |
| Image pull backoff | Check image name/tag, registry credentials, and network access to registry |

---

### Issue 2: Pods in `CrashLoopBackOff`

**Symptoms:** Pods start, crash, and restart repeatedly.

**Diagnosis:**
```bash
kubectl logs POD_NAME -n soc-agent --previous --tail=50
kubectl describe pod POD_NAME -n soc-agent | grep -A 5 "Last State"
```

**Common Causes:**

| Cause | Log Pattern | Resolution |
|-------|-------------|-----------|
| Missing environment variable | `KeyError: 'DATABASE_URL'` | Verify all required secrets are mounted |
| Database unreachable | `OperationalError: could not connect` | Check DB host, firewall, credentials |
| Redis unreachable | `ConnectionError: Error connecting to Redis` | Check Redis host, firewall, credentials |
| Port already in use | `Address already in use` | Check for duplicate deployments or port conflicts |
| Python import error | `ModuleNotFoundError` | Image may be corrupted; rebuild and push |

---

### Issue 3: API returns 401 Unauthorized

**Symptoms:** All API calls return 401 even with valid-looking tokens.

**Diagnosis:**
```bash
# Decode JWT token (without verification) to inspect claims
echo "TOKEN_HERE" | cut -d. -f2 | base64 -d 2>/dev/null | python -m json.tool

# Check server clock
kubectl exec -n soc-agent deploy/soc-agent-api -- date -u

# Check JWT public key
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -s http://localhost:8000/.well-known/jwks.json | python -m json.tool
```

**Causes and Resolutions:**

| Cause | Resolution |
|-------|-----------|
| Token expired | Obtain a new token via `/api/v1/auth/token` |
| Clock skew between client and server | Sync NTP on all systems. JWT allows 30s leeway by default. |
| JWT signing key was rotated | Old tokens are invalid. Re-authenticate to get tokens signed with the new key. |
| Wrong audience or issuer | Verify `JWT_AUDIENCE` and `JWT_ISSUER` environment variables match token claims |

---

### Issue 4: API returns 403 Forbidden

**Symptoms:** Authenticated requests return 403 for specific endpoints.

**Diagnosis:**
```bash
# Check user's role in the token
echo "TOKEN_HERE" | cut -d. -f2 | base64 -d 2>/dev/null | python -c "import sys,json; print(json.load(sys.stdin).get('roles'))"
```

**Resolution:** The user's role does not have permission for the requested action. See the RBAC permission matrix in `security-model.md`. Upgrade the user's role if appropriate.

---

### Issue 5: Slow API responses (>5 seconds)

**Symptoms:** Dashboard is sluggish, API calls take long to respond.

**Diagnosis:**
```bash
# Check API response times
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -s http://localhost:8000/metrics | grep soc_agent_http_request_duration

# Check database query performance
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -s http://localhost:8000/metrics | grep soc_agent_db_query_duration

# Check pod CPU/memory
kubectl top pods -n soc-agent -l component=api
```

**Causes and Resolutions:**

| Cause | Resolution |
|-------|-----------|
| Database queries slow | Add missing indexes. Check `pg_stat_user_tables` for sequential scans on large tables. |
| Connection pool exhausted | See Runbook 5 (Database Connection Pool Exhaustion) |
| Too many concurrent requests | Scale API pods or add rate limiting |
| Large result sets | Add pagination. Set `limit` parameter on list endpoints. |
| Redis slow | Check Redis memory usage and eviction policy. Consider Redis cluster mode. |

---

### Issue 6: SIEM alerts not appearing in dashboard

**Symptoms:** SIEM has active alerts but agent dashboard shows none.

**Diagnosis:**
```bash
# Check health endpoint
curl -s https://soc-agent.company.com/health | python -m json.tool

# Check connector logs
kubectl logs -n soc-agent -l component=connector --tail=100

# Check ingestion metrics
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -s http://localhost:8000/metrics | grep soc_agent_alerts_ingested_total
```

**Causes and Resolutions:**

| Cause | Resolution |
|-------|-----------|
| SIEM connector not running | `kubectl get pods -n soc-agent -l component=connector` -- restart if needed |
| SIEM credentials invalid | Update credentials in secret manager, restart connector |
| SIEM query returns no results | Check SIEM search query parameters. Verify time range and index coverage. |
| Alerts being deduplicated | Check `soc_agent_alerts_deduplicated_total`. Adjust dedup window if too aggressive. |
| Connector polling interval too long | Reduce `SIEM_POLL_INTERVAL_SECONDS` |

---

### Issue 7: Enrichment data missing on alerts

**Symptoms:** Alerts show "Not enriched" or "Pending enrichment" status.

**Diagnosis:**
```bash
kubectl logs -n soc-agent -l component=worker --tail=200 | grep -i "enrich"
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -s http://localhost:8000/metrics | grep soc_agent_enrichment
```

**Causes:** Rate limiting (see Runbook 4), TI API down, worker pods not running, Redis cache cleared.

**Resolution:** Trigger re-enrichment for pending alerts:
```bash
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  curl -X POST http://localhost:8000/api/v1/admin/enrichment/retry-pending \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

### Issue 8: Dashboard login fails (OAuth)

**Symptoms:** Clicking "Login" redirects to IdP but returns with an error.

**Diagnosis:**
```bash
# Check API logs during login attempt
kubectl logs -n soc-agent -l component=api --tail=50 | grep -i "oauth\|auth\|callback"
```

**Causes and Resolutions:**

| Cause | Resolution |
|-------|-----------|
| Redirect URI mismatch | Update `OAUTH_REDIRECT_URI` to match the URI registered in the IdP |
| Client ID/secret invalid | Verify OAuth app configuration in the IdP admin console |
| OIDC discovery endpoint unreachable | Check network access to the IdP's `.well-known/openid-configuration` URL |
| Clock skew | OIDC tokens have strict timestamp validation. Sync NTP. |

---

### Issue 9: Helm upgrade fails

**Symptoms:** `helm upgrade` command returns an error or times out.

**Diagnosis:**
```bash
helm status soc-analyst-agent -n soc-agent
helm history soc-analyst-agent -n soc-agent
kubectl get events -n soc-agent --sort-by='.lastTimestamp' | tail -20
```

**Causes and Resolutions:**

| Cause | Resolution |
|-------|-----------|
| Resource quota exceeded | Check `kubectl describe resourcequota -n soc-agent`. Increase quota or reduce replicas. |
| Invalid values file | Validate YAML syntax. Run `helm template` to preview rendered manifests. |
| Previous release in failed state | `helm rollback soc-analyst-agent LAST_GOOD_REVISION -n soc-agent` |
| Image not found in registry | Verify image tag exists: `docker manifest inspect REGISTRY/soc-analyst-agent:TAG` |

---

### Issue 10: Database migration fails

**Symptoms:** Migration Job fails. Application pods crash because schema is out of date.

**Diagnosis:**
```bash
kubectl logs job/soc-agent-migrate -n soc-agent
```

**Causes and Resolutions:**

| Cause | Resolution |
|-------|-----------|
| Migration user lacks DDL permissions | Grant `CREATE TABLE`, `ALTER TABLE` to migration user |
| Conflicting migration state | Check `alembic_version` table. If stuck, manually set to the correct revision. |
| Table already exists (re-run) | Alembic should handle this. If not, check for manual schema changes outside Alembic. |

---

### Issue 11: PagerDuty notifications not received

**Symptoms:** Critical alerts fire in Prometheus but no PagerDuty page.

**Diagnosis:**
```bash
# Check AlertManager
kubectl logs -n monitoring deploy/alertmanager --tail=100 | grep -i "pagerduty\|error"

# Check if alert is firing
kubectl exec -n monitoring deploy/prometheus -- \
  wget -q -O- http://localhost:9090/api/v1/alerts | python -m json.tool
```

**Causes:** Integration key incorrect, AlertManager route misconfigured, PagerDuty service disabled.

---

### Issue 12: High CPU usage on worker pods

**Symptoms:** Worker pods consuming >80% CPU sustained.

**Diagnosis:**
```bash
kubectl top pods -n soc-agent -l component=worker
```

**Resolution:** Scale workers horizontally. If a single worker is stuck, check for infinite loops in task processing logs.

---

### Issue 13: Redis memory full

**Symptoms:** Logs show `OOM command not allowed when used memory > maxmemory`. Workers fail to enqueue tasks.

**Resolution:**
```bash
# Check Redis memory
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  python -c "import redis; r=redis.from_url('rediss://...'); print(r.info('memory'))"

# Clear expired cache entries
kubectl exec -n soc-agent deploy/soc-agent-api -- \
  python -c "import redis; r=redis.from_url('rediss://...'); print('Keys before:', r.dbsize()); # eviction is automatic with allkeys-lru"
```

Increase Redis `maxmemory` or upgrade instance size.

---

### Issue 14: TLS certificate verification failures for SIEM

**Symptoms:** Connector logs show `SSLCertVerificationError` or `CERTIFICATE_VERIFY_FAILED`.

**Resolution:** The SIEM's TLS certificate is self-signed or uses an internal CA. Add the CA certificate to the agent's trust store:
```bash
kubectl create configmap soc-agent-ca-bundle \
  -n soc-agent \
  --from-file=ca.crt=/path/to/internal-ca.crt

# Mount in pod and set REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca.crt
```

---

### Issue 15: Containment action fails

**Symptoms:** SOC lead approves containment but the endpoint is not isolated.

**Diagnosis:**
```bash
kubectl logs -n soc-agent -l component=api --tail=100 | grep -i "containment"
```

**Causes:** CrowdStrike API credentials expired, host ID not found, Falcon sensor offline on target host.

---

### Issue 16: Audit logs table growing too large

**Symptoms:** PostgreSQL disk usage increasing rapidly. Queries on `audit_logs` are slow.

**Resolution:**
```bash
# Check table size
kubectl run pg-size --rm -it --image=postgres:16-alpine --restart=Never -- \
  psql "$DATABASE_URL" -c "SELECT pg_size_pretty(pg_total_relation_size('audit_logs'));"

# Archive old audit logs to S3 (use export API)
# Then partition the table by month for better query performance
```

---

### Issue 17: Alert correlation producing too many or too few incidents

**Resolution:** Adjust `CORRELATION_WINDOW_HOURS` and `CORRELATION_SIMILARITY_THRESHOLD` environment variables. Default window is 24 hours, threshold is 0.7.

---

### Issue 18: MITRE ATT&CK mappings are incorrect

**Resolution:** Override mappings via the dashboard or API. Submit feedback to improve the classification model. Increase `MITRE_MAPPING_MIN_CONFIDENCE` to filter low-confidence mappings.

---

### Issue 19: Scheduled tasks (Celery Beat) not running

**Symptoms:** Data retention cleanup, re-enrichment, and report generation are not executing.

**Diagnosis:**
```bash
kubectl get pods -n soc-agent -l component=beat
kubectl logs -n soc-agent -l component=beat --tail=50
```

**Resolution:** Only one Beat pod should run at a time. If it is crashed, restart: `kubectl rollout restart deployment/soc-agent-beat -n soc-agent`.

---

### Issue 20: Ingress returning 502 Bad Gateway

**Symptoms:** External requests to the agent return 502.

**Diagnosis:**
```bash
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx --tail=50
kubectl get endpoints soc-agent-api -n soc-agent
```

**Causes:** No healthy backend pods, readiness probe failing, service port mismatch.

**Resolution:** Check pod readiness. Verify the Service port matches the container port (8000). Check ingress annotations for correct backend protocol.

---

### Issue 21: Data export taking too long or timing out

**Resolution:** Reduce the date range or add filters. For large exports, use the async export API which writes results to S3/Blob storage and sends a notification when complete.

---

### Issue 22: WebSocket disconnections on dashboard

**Symptoms:** Dashboard real-time updates stop. Page shows "Reconnecting..." banner.

**Causes:** Ingress proxy timeout (default 60s for WebSocket), network instability.

**Resolution:** Increase ingress WebSocket timeout:
```yaml
nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
```
