# IAM Permissions

**Last Updated:** 2026-06-28
**Version:** 1.0

This document specifies the minimum IAM permissions required to deploy and operate the SOC Analyst Agent on each supported cloud provider and within Kubernetes.

---

## 1. AWS IAM Policy

### 1.1 EKS Node Group IAM Role

This policy is attached to the IAM role associated with the EKS managed node group running the agent pods.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsManagerRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:*:*:secret:soc-analyst-agent/*"
      ]
    },
    {
      "Sid": "KMSDecrypt",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": [
        "arn:aws:kms:*:*:key/KEY_ID_FOR_SOC_AGENT"
      ]
    },
    {
      "Sid": "S3ArtifactAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::soc-analyst-agent-artifacts",
        "arn:aws:s3:::soc-analyst-agent-artifacts/*"
      ]
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/soc-analyst-agent/*"
      ]
    },
    {
      "Sid": "CloudWatchMetrics",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "cloudwatch:namespace": "SOCAnalystAgent"
        }
      }
    },
    {
      "Sid": "ECRPull",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    }
  ]
}
```

### 1.2 CI/CD Deployment IAM Role

This role is used by the CI/CD pipeline to deploy Helm charts and manage infrastructure.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EKSAccess",
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": [
        "arn:aws:eks:*:*:cluster/soc-agent-cluster"
      ]
    },
    {
      "Sid": "ECRPush",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage"
      ],
      "Resource": [
        "arn:aws:ecr:*:*:repository/soc-analyst-agent"
      ]
    },
    {
      "Sid": "SecretsManagerWrite",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:UpdateSecret",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:*:*:secret:soc-analyst-agent/*"
      ]
    },
    {
      "Sid": "RDSManagement",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 2. Azure RBAC Roles

### 2.1 AKS Pod Managed Identity

Assign these Azure RBAC roles to the user-assigned managed identity used by the agent pods.

| Role | Scope | Purpose |
|------|-------|---------|
| Key Vault Secrets User | Resource Group: `rg-soc-agent` | Read secrets from Azure Key Vault |
| Storage Blob Data Contributor | Storage Account: `socanlystartstorage` | Read/write alert artifacts and exports |
| Monitoring Metrics Publisher | Resource Group: `rg-soc-agent` | Publish custom metrics to Azure Monitor |
| Microsoft Sentinel Responder | Resource Group: `rg-sentinel` | Read/update Sentinel incidents and alerts |
| Log Analytics Reader | Log Analytics Workspace | Execute KQL queries for alert data |

**Azure CLI commands to assign roles:**

```bash
# Get managed identity principal ID
PRINCIPAL_ID=$(az identity show \
  --name soc-agent-identity \
  --resource-group rg-soc-agent \
  --query principalId -o tsv)

# Key Vault Secrets User
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "$PRINCIPAL_ID" \
  --scope "/subscriptions/{sub-id}/resourceGroups/rg-soc-agent/providers/Microsoft.KeyVault/vaults/soc-agent-vault"

# Storage Blob Data Contributor
az role assignment create \
  --role "Storage Blob Data Contributor" \
  --assignee "$PRINCIPAL_ID" \
  --scope "/subscriptions/{sub-id}/resourceGroups/rg-soc-agent/providers/Microsoft.Storage/storageAccounts/socanlystartstorage"

# Monitoring Metrics Publisher
az role assignment create \
  --role "Monitoring Metrics Publisher" \
  --assignee "$PRINCIPAL_ID" \
  --scope "/subscriptions/{sub-id}/resourceGroups/rg-soc-agent"

# Microsoft Sentinel Responder
az role assignment create \
  --role "Microsoft Sentinel Responder" \
  --assignee "$PRINCIPAL_ID" \
  --scope "/subscriptions/{sub-id}/resourceGroups/rg-sentinel"

# Log Analytics Reader
az role assignment create \
  --role "Log Analytics Reader" \
  --assignee "$PRINCIPAL_ID" \
  --scope "/subscriptions/{sub-id}/resourceGroups/rg-sentinel/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace"
```

### 2.2 CI/CD Service Principal

| Role | Scope | Purpose |
|------|-------|---------|
| Azure Kubernetes Service Cluster User Role | AKS Cluster | Deploy Helm charts to AKS |
| AcrPush | Container Registry | Push container images |
| Key Vault Secrets Officer | Key Vault | Create and update secrets |

---

## 3. GCP IAM Roles

### 3.1 GKE Workload Identity

Bind these IAM roles to the Google Service Account used by the agent's Kubernetes ServiceAccount via Workload Identity.

| Role | Resource | Purpose |
|------|----------|---------|
| `roles/secretmanager.secretAccessor` | Project | Access secrets from GCP Secret Manager |
| `roles/storage.objectAdmin` | Bucket: `soc-agent-artifacts` | Read/write alert artifacts and exports |
| `roles/monitoring.metricWriter` | Project | Write custom metrics to Cloud Monitoring |
| `roles/logging.logWriter` | Project | Write structured logs to Cloud Logging |

**gcloud commands:**

```bash
# Create Google Service Account
gcloud iam service-accounts create soc-agent-sa \
  --display-name="SOC Analyst Agent Service Account"

# Bind roles
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:soc-agent-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:soc-agent-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/monitoring.metricWriter"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:soc-agent-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"

gsutil iam ch \
  serviceAccount:soc-agent-sa@PROJECT_ID.iam.gserviceaccount.com:roles/storage.objectAdmin \
  gs://soc-agent-artifacts

# Bind Kubernetes SA to Google SA (Workload Identity)
gcloud iam service-accounts add-iam-policy-binding \
  soc-agent-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:PROJECT_ID.svc.id.goog[soc-agent/soc-agent-api]"
```

### 3.2 CI/CD Service Account

| Role | Resource | Purpose |
|------|----------|---------|
| `roles/container.developer` | GKE Cluster | Deploy to GKE |
| `roles/artifactregistry.writer` | Artifact Registry repo | Push container images |
| `roles/secretmanager.admin` | Project | Manage secrets during deployment |

---

## 4. Kubernetes RBAC

### 4.1 ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: soc-agent-api
  namespace: soc-agent
  annotations:
    # AWS EKS
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/soc-agent-pod-role
    # GCP GKE
    iam.gke.io/gcp-service-account: soc-agent-sa@PROJECT_ID.iam.gserviceaccount.com
    # Azure AKS
    azure.workload.identity/client-id: CLIENT_ID_OF_MANAGED_IDENTITY
```

### 4.2 Role (Namespace-Scoped)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: soc-agent-role
  namespace: soc-agent
rules:
  # Read own pods for health checking
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  # Read ConfigMaps for configuration
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
  # Read Secrets for credential access
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  # Create Jobs for scheduled tasks
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "delete"]
  # Read own events
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list"]
```

### 4.3 RoleBinding

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: soc-agent-rolebinding
  namespace: soc-agent
subjects:
  - kind: ServiceAccount
    name: soc-agent-api
    namespace: soc-agent
roleRef:
  kind: Role
  name: soc-agent-role
  apiGroup: rbac.authorization.k8s.io
```

### 4.4 ClusterRole (Cluster-Scoped, Minimal)

Only required if the agent needs to read cluster-wide resources (e.g., node status for capacity reporting).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: soc-agent-cluster-role
rules:
  # Read node status for resource monitoring
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list"]
  # Read namespaces for multi-namespace alerting
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list"]
```

### 4.5 ClusterRoleBinding

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: soc-agent-cluster-rolebinding
subjects:
  - kind: ServiceAccount
    name: soc-agent-api
    namespace: soc-agent
roleRef:
  kind: ClusterRole
  name: soc-agent-cluster-role
  apiGroup: rbac.authorization.k8s.io
```

---

## 5. Database User Permissions

### 5.1 Application User (`soc_agent_app`)

```sql
-- Create application user
CREATE USER soc_agent_app WITH PASSWORD 'STORED_IN_SECRET_MANAGER';

-- Grant connect
GRANT CONNECT ON DATABASE soc_analyst_agent TO soc_agent_app;

-- Grant usage on schema
GRANT USAGE ON SCHEMA public TO soc_agent_app;

-- Grant DML on all tables
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO soc_agent_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO soc_agent_app;

-- Grant sequence usage (for auto-increment IDs)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO soc_agent_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO soc_agent_app;

-- Explicitly deny DELETE on audit_logs
REVOKE DELETE ON TABLE audit_logs FROM soc_agent_app;
REVOKE TRUNCATE ON TABLE audit_logs FROM soc_agent_app;
```

### 5.2 Migration User (`soc_agent_migrate`)

Used only during deployment for schema migrations.

```sql
-- Create migration user
CREATE USER soc_agent_migrate WITH PASSWORD 'STORED_IN_SECRET_MANAGER';

-- Grant connect
GRANT CONNECT ON DATABASE soc_analyst_agent TO soc_agent_migrate;

-- Grant schema management
GRANT CREATE ON SCHEMA public TO soc_agent_migrate;
GRANT USAGE ON SCHEMA public TO soc_agent_migrate;

-- Grant DDL operations
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO soc_agent_migrate;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO soc_agent_migrate;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO soc_agent_migrate;
```

### 5.3 Read-Only User (`soc_agent_readonly`)

For reporting, dashboards, and ad-hoc queries.

```sql
-- Create read-only user
CREATE USER soc_agent_readonly WITH PASSWORD 'STORED_IN_SECRET_MANAGER';

-- Grant connect
GRANT CONNECT ON DATABASE soc_analyst_agent TO soc_agent_readonly;

-- Grant read-only access
GRANT USAGE ON SCHEMA public TO soc_agent_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO soc_agent_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO soc_agent_readonly;
```

---

## 6. Principle of Least Privilege Checklist

- [ ] Cloud IAM roles grant access only to resources prefixed with `soc-analyst-agent` or in the `soc-agent` resource group
- [ ] No wildcard (`*`) resource ARNs except where required by the cloud provider (e.g., ECR auth token)
- [ ] Kubernetes ServiceAccount has no cluster-admin privileges
- [ ] Database application user cannot DROP tables, CREATE users, or modify server configuration
- [ ] CI/CD service principal cannot access production secrets in other projects
- [ ] API keys for external services (SIEM, TI) have the minimum required scope
- [ ] All IAM permissions are documented and reviewed quarterly
