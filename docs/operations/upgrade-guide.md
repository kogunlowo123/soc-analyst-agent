# Upgrade Guide

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## 1. Version Upgrade Procedure

### 1.1 Pre-Upgrade Checklist

Complete before starting any upgrade:

- [ ] Read the release notes for the target version, paying attention to breaking changes
- [ ] Verify the target version is listed in the compatibility matrix
- [ ] Back up PostgreSQL database (full snapshot or `pg_dump`)
- [ ] Verify current deployment is healthy (`helm status soc-analyst-agent -n soc-agent`)
- [ ] Verify all pods are Running (`kubectl get pods -n soc-agent`)
- [ ] Record current Helm revision number (`helm history soc-analyst-agent -n soc-agent | tail -1`)
- [ ] Notify SOC team of planned maintenance window (even though upgrades are zero-downtime, notify as a precaution)
- [ ] Verify CI/CD pipeline has built and pushed the new image tag
- [ ] Test the new image in a staging environment first
- [ ] Review database migration scripts for the new version (if any)

### 1.2 Upgrade Steps

#### Step 1: Pull the New Image

```bash
# Verify image exists in registry
docker manifest inspect your-registry.com/soc-analyst-agent:v1.1.0

# Or for ECR
aws ecr describe-images \
  --repository-name soc-analyst-agent \
  --image-ids imageTag=v1.1.0
```

#### Step 2: Run Database Migrations (If Required)

Check release notes. If the new version includes database migrations:

```bash
# Run migration as a Kubernetes Job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: soc-agent-migrate-v1-1-0
  namespace: soc-agent
spec:
  template:
    spec:
      serviceAccountName: soc-agent-api
      containers:
        - name: migrate
          image: your-registry.com/soc-analyst-agent:v1.1.0
          command: ["alembic", "upgrade", "head"]
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: soc-agent-db
                  key: migrate-url
      restartPolicy: Never
  backoffLimit: 3
EOF

# Wait for completion
kubectl wait --for=condition=complete job/soc-agent-migrate-v1-1-0 -n soc-agent --timeout=300s

# Verify success
kubectl logs job/soc-agent-migrate-v1-1-0 -n soc-agent
```

#### Step 3: Update Helm Values (If Configuration Changed)

Compare the new version's default values with your current values file:

```bash
# Diff default values
helm show values ./infrastructure/helm/soc-analyst-agent > new-defaults.yaml
diff values-production.yaml new-defaults.yaml
```

Update `values-production.yaml` with any new required values.

#### Step 4: Perform the Helm Upgrade

```bash
helm upgrade soc-analyst-agent \
  ./infrastructure/helm/soc-analyst-agent \
  --namespace soc-agent \
  --values values-production.yaml \
  --set image.tag=v1.1.0 \
  --wait \
  --timeout 10m \
  --atomic
```

The `--atomic` flag ensures that if any pod fails to become ready, the entire upgrade is automatically rolled back.

#### Step 5: Verify the Upgrade

```bash
# Check all pods are running with the new image
kubectl get pods -n soc-agent -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}'

# Check health endpoint
curl -s https://soc-agent.company.com/health | python -m json.tool

# Verify version in health response
curl -s https://soc-agent.company.com/health | python -c "import sys,json; print('Version:', json.load(sys.stdin).get('version'))"

# Run smoke tests
# (see production-deployment.md Section 6)

# Check logs for errors
kubectl logs -n soc-agent -l app.kubernetes.io/name=soc-analyst-agent --since=5m | grep -c ERROR
```

#### Step 6: Monitor Post-Upgrade

Monitor for 30 minutes after upgrade:

- Check Grafana dashboard for error rate spikes
- Verify alert processing is continuing (`soc_agent_alerts_processed_total` is increasing)
- Verify SIEM connectivity is maintained
- Verify enrichment is functioning

#### Step 7: Clean Up

```bash
# Delete migration job
kubectl delete job soc-agent-migrate-v1-1-0 -n soc-agent

# Clean up old image tags from registry (optional)
# Keep at least the 3 most recent versions for rollback capability
```

---

## 2. Database Migration

### 2.1 Migration Strategy

All database schema changes are managed by Alembic (SQLAlchemy's migration tool). Migrations follow these principles:

- **Forward-compatible:** New columns are always nullable or have defaults, so the previous application version can still function during the rolling update.
- **Backward-compatible:** Migrations are designed so that `alembic downgrade` reverses the change without data loss (where possible).
- **Idempotent:** Running a migration that has already been applied is a no-op.

### 2.2 Migration Workflow

```
1. alembic upgrade head       # Apply all pending migrations
2. Rolling deployment starts  # New pods start with new code
3. Old pods drain gracefully  # Old code still works with new schema
4. Rolling deployment ends    # All pods running new code
```

### 2.3 Handling Large Migrations

For migrations that alter large tables (>1M rows), the migration is split into phases:

**Phase 1 (Pre-upgrade):** Add new columns, create new indexes concurrently.
**Phase 2 (Application upgrade):** Deploy new code that writes to both old and new columns.
**Phase 3 (Post-upgrade):** Backfill data, drop old columns.

This prevents long lock times on production tables.

### 2.4 Verifying Migration State

```bash
# Check current migration version
kubectl run pg-version --rm -it --image=postgres:16-alpine --restart=Never -- \
  psql "$DATABASE_URL" -c "SELECT version_num FROM alembic_version;"

# List all available migrations
kubectl run alembic-history --rm -it \
  --image=your-registry.com/soc-analyst-agent:v1.1.0 \
  --restart=Never -- \
  alembic history --verbose
```

---

## 3. Rollback Procedure

### 3.1 Helm Rollback

```bash
# List release history
helm history soc-analyst-agent -n soc-agent

# RELEASE   REVISION  STATUS      CHART                       APP VERSION
# soc-...   1         superseded  soc-analyst-agent-1.0.0     1.0.0
# soc-...   2         deployed    soc-analyst-agent-1.1.0     1.1.0

# Rollback to previous revision
helm rollback soc-analyst-agent 1 -n soc-agent --wait --timeout 5m

# Verify rollback
kubectl get pods -n soc-agent -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' | sort -u
```

### 3.2 Database Rollback

If the upgrade included database migrations:

```bash
# Identify the migration revision to rollback to
# (Check the previous version's migration head)

# Run downgrade
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: soc-agent-rollback-db
  namespace: soc-agent
spec:
  template:
    spec:
      serviceAccountName: soc-agent-api
      containers:
        - name: rollback
          image: your-registry.com/soc-analyst-agent:v1.0.0
          command: ["alembic", "downgrade", "-1"]
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: soc-agent-db
                  key: migrate-url
      restartPolicy: Never
  backoffLimit: 1
EOF

kubectl wait --for=condition=complete job/soc-agent-rollback-db -n soc-agent --timeout=300s
```

### 3.3 Point-in-Time Recovery

For catastrophic failures (data corruption, accidental mass deletion):

1. Stop all agent pods: `kubectl scale deployment -n soc-agent --all --replicas=0`
2. Restore PostgreSQL from the pre-upgrade snapshot
3. Helm rollback to the previous version
4. Scale pods back up
5. Verify data integrity

### 3.4 Rollback Decision Guide

| Scenario | Recommended Action |
|----------|-------------------|
| New version crashes on startup | Helm rollback (no DB rollback needed if migration was forward-compatible) |
| Performance degradation | Helm rollback |
| Subtle data issues discovered | Helm rollback + investigate before re-upgrading |
| Database migration failed mid-way | Database rollback (Alembic downgrade) + Helm rollback |
| Data corruption discovered | STOP all pods. Point-in-time recovery. Engage database team. |

---

## 4. Breaking Changes Checklist

Before upgrading, review the release notes for these types of breaking changes:

### 4.1 Configuration Changes

- [ ] New required environment variables added? Update your values file and secrets.
- [ ] Environment variable names changed? Update references in ConfigMaps and secrets.
- [ ] Default values changed that affect behavior? Review and explicitly set in your values file.

### 4.2 API Changes

- [ ] API endpoints renamed or removed? Update SOAR playbooks, scripts, and integrations.
- [ ] Request/response schema changed? Update API consumers.
- [ ] Authentication method changed? Update client configurations.

### 4.3 Database Changes

- [ ] Destructive migration (column removal, type change)? Plan for extended migration window.
- [ ] New required columns without defaults? Ensure data backfill is handled.
- [ ] Index changes on large tables? Schedule during low-traffic period.

### 4.4 Dependency Changes

- [ ] Python version requirement changed? Update base image.
- [ ] Kubernetes minimum version increased? Verify cluster version.
- [ ] Redis version requirement changed? Upgrade Redis before agent.

### 4.5 Behavioral Changes

- [ ] Alert processing logic changed? Review for impact on existing workflows.
- [ ] MITRE mapping algorithm updated? Expect mapping changes; review with SOC team.
- [ ] Default RBAC permissions changed? Review user access.

---

## 5. Version-Specific Upgrade Notes

### Upgrading from 1.0.x to 1.1.x

**Breaking Changes:** None.

**New Features:**
- Enhanced MITRE ATT&CK mapping with transformer-based NLP model (optional, set `NLP_MODEL_TYPE=transformer`)
- Bulk alert operations API
- Dashboard dark mode

**Migration:** One migration adding `alerts.mitre_confidence_score` column (nullable float, no data backfill required).

**Steps:**
1. Run standard upgrade procedure (Section 1.2)
2. Optionally enable new NLP model after verifying performance with test alerts

---

### Upgrading from 1.1.x to 1.2.x

**Breaking Changes:**
- `SIEM_POLL_INTERVAL` environment variable renamed to `SIEM_POLL_INTERVAL_SECONDS` (now requires integer seconds instead of duration string)
- `/api/v1/alerts/search` response now returns `items` array instead of `results` array

**New Features:**
- OpenSearch 2.x support as an alternative to Elasticsearch
- Alert tagging and custom fields
- Improved deduplication with configurable similarity threshold

**Migration:** Two migrations: (1) adding `alert_tags` table, (2) adding `alerts.custom_fields` JSONB column.

**Steps:**
1. Update `SIEM_POLL_INTERVAL` to `SIEM_POLL_INTERVAL_SECONDS` in your values file
2. Update any scripts or integrations that parse the `/api/v1/alerts/search` response to use `items` instead of `results`
3. Run standard upgrade procedure (Section 1.2)

---

## 6. Staging Verification

Always test upgrades in staging before production:

```bash
# Deploy to staging
helm upgrade --install soc-analyst-agent-staging \
  ./infrastructure/helm/soc-analyst-agent \
  --namespace soc-agent-staging \
  --values values-staging.yaml \
  --set image.tag=v1.1.0 \
  --wait --timeout 10m

# Run automated test suite against staging
pytest tests/e2e/ \
  --base-url=https://soc-agent-staging.company.com \
  --api-key=$STAGING_API_KEY

# Verify staging for at least 2 hours before promoting to production
```
