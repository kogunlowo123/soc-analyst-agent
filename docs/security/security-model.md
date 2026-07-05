# Security Model

**Last Updated:** 2026-06-28
**Version:** 1.0

---

## 1. Authentication

### 1.1 JWT Token Authentication (API)

All API requests are authenticated using JSON Web Tokens (JWT) signed with RS256 (RSA-SHA256).

**Token Structure:**

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "soc-agent-key-2026"
  },
  "payload": {
    "sub": "user-uuid-here",
    "iss": "soc-analyst-agent",
    "aud": "soc-analyst-agent-api",
    "exp": 1751673600,
    "iat": 1751670000,
    "roles": ["soc_analyst"],
    "org_id": "org-uuid-here",
    "jti": "unique-token-id"
  }
}
```

**Token Lifecycle:**
- Access tokens expire after 1 hour (`ACCESS_TOKEN_EXPIRE_MINUTES=60`)
- Refresh tokens expire after 7 days (`REFRESH_TOKEN_EXPIRE_DAYS=7`)
- Refresh tokens are stored as SHA-256 hashes in PostgreSQL
- Token rotation: issuing a new access token via refresh invalidates the previous access token
- Revocation: tokens can be revoked immediately via the `/api/v1/auth/revoke` endpoint

**Key Management:**
- RSA key pair (4096-bit) generated during initial setup
- Private key stored in HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager
- Public key served at `/.well-known/jwks.json` for token verification by downstream services
- Key rotation: new key pairs are generated quarterly; both old and new keys are accepted during a 24-hour overlap window

### 1.2 API Key Authentication (Service-to-Service)

For machine-to-machine integrations (webhooks, CI/CD pipelines, SOAR platforms), API keys are supported as an alternative to JWT.

**API Key Format:** 64-character hex string prefixed with `soc_` (e.g., `soc_a1b2c3d4...`)

**Storage:** API keys are stored as SHA-256 hashes in PostgreSQL. The plaintext key is shown only once at creation time.

**Usage:** Passed via `X-API-Key` header or `Authorization: ApiKey <key>` header.

**Scope:** Each API key is associated with a role and can be restricted to specific IP CIDR ranges.

**Rotation:** API keys can be rotated without downtime using the dual-key pattern: create a new key, update consumers, then revoke the old key.

### 1.3 OAuth 2.0 PKCE (Dashboard)

The web dashboard uses OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) for browser-based authentication.

**Supported Identity Providers:**
- Azure Active Directory (Microsoft Entra ID)
- Okta
- Google Workspace
- Any OIDC-compliant provider

**Configuration:**
- `OAUTH_PROVIDER_URL`: OIDC discovery endpoint (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`)
- `OAUTH_CLIENT_ID`: Client ID registered with the IdP
- `OAUTH_REDIRECT_URI`: Callback URL (e.g., `https://soc-agent.company.com/auth/callback`)
- No client secret is stored in the browser (PKCE eliminates this requirement)

**Session Management:**
- Sessions stored server-side in Redis with a 12-hour TTL
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- Idle timeout: 30 minutes of inactivity triggers re-authentication
- Concurrent session limit: 3 sessions per user (oldest session is invalidated)

---

## 2. Authorization

### 2.1 Role-Based Access Control (RBAC)

| Role | Description | Permissions |
|------|-------------|-------------|
| `soc_analyst` | Tier 1/2 SOC analyst | View alerts, view incidents, add investigation notes, view enrichment data, view dashboards |
| `soc_lead` | SOC shift lead / Tier 3 | All analyst permissions + approve containment actions, close incidents, assign incidents, modify alert priority |
| `soc_manager` | SOC manager | All lead permissions + view operational metrics, manage analyst accounts, configure notification channels, export data |
| `admin` | Platform administrator | All manager permissions + manage SIEM connections, manage API keys, manage roles, view audit logs, modify system configuration |

### 2.2 Permission Matrix

| Action | soc_analyst | soc_lead | soc_manager | admin |
|--------|:-----------:|:--------:|:-----------:|:-----:|
| View alerts | Yes | Yes | Yes | Yes |
| View alert enrichment | Yes | Yes | Yes | Yes |
| Add investigation notes | Yes | Yes | Yes | Yes |
| Update alert status | Yes | Yes | Yes | Yes |
| View incidents | Yes | Yes | Yes | Yes |
| Create incidents | No | Yes | Yes | Yes |
| Close incidents | No | Yes | Yes | Yes |
| Assign incidents | No | Yes | Yes | Yes |
| Approve containment | No | Yes | Yes | Yes |
| Execute containment | No | Yes | Yes | Yes |
| View metrics dashboard | Yes | Yes | Yes | Yes |
| View operational reports | No | No | Yes | Yes |
| Export alert/incident data | No | No | Yes | Yes |
| Manage users | No | No | Yes | Yes |
| Manage SIEM connections | No | No | No | Yes |
| Manage API keys | No | No | No | Yes |
| View audit logs | No | No | No | Yes |
| Modify system config | No | No | No | Yes |

### 2.3 Permission Enforcement

Permissions are enforced at three layers:

1. **API Gateway:** JWT claims are validated, and the `roles` array is checked against route-level permission requirements.
2. **Application Layer:** FastAPI dependency injection checks role membership before executing business logic.
3. **Database Layer:** Row-level security is not implemented; authorization is enforced entirely at the application layer.

---

## 3. Data Encryption

### 3.1 Encryption in Transit

All network communication uses TLS 1.3 (minimum TLS 1.2).

| Connection | Protocol | Notes |
|-----------|----------|-------|
| Client to API/Dashboard | TLS 1.3 | Terminated at ingress controller or load balancer |
| API to PostgreSQL | TLS 1.2+ | Enforced via `sslmode=verify-full` in connection string |
| API to Redis | TLS 1.2+ | Enforced via `rediss://` URI scheme |
| API to SIEM APIs | TLS 1.2+ | Governed by SIEM endpoint configuration |
| API to TI APIs | TLS 1.3 | All TI APIs enforce HTTPS |
| Pod-to-Pod (mTLS) | TLS 1.3 | Via service mesh (Istio/Linkerd) or Kubernetes NetworkPolicy |

**TLS Configuration:**
- Cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256
- HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Certificate pinning: not enforced (managed certificates rotate frequently)

### 3.2 Encryption at Rest

| Data Store | Encryption Method | Key Management |
|-----------|-------------------|----------------|
| PostgreSQL | AES-256-GCM (cloud-managed or LUKS) | Cloud KMS (AWS KMS, Azure Key Vault, GCP KMS) |
| Redis | AES-256 (cloud-managed) | Cloud KMS for managed Redis; application-layer encryption for self-hosted |
| S3/Blob Storage | AES-256-GCM (SSE-KMS) | Cloud KMS with customer-managed keys (CMK) |
| Kubernetes Secrets | AES-256-CBC (etcd encryption) | KMS provider configured in API server |
| Backup Archives | AES-256-GCM | Key stored in Vault/KMS, not alongside backups |

### 3.3 Sensitive Field Encryption

Specific database columns containing PII or sensitive data are encrypted at the application layer before storage:

- `api_keys.key_hash` — SHA-256 hash (one-way)
- `users.email` — AES-256-GCM encrypted
- `siem_connections.credentials` — AES-256-GCM encrypted with per-connection nonce
- `incidents.affected_users` — AES-256-GCM encrypted

Encryption keys for application-layer encryption are retrieved from the secret manager at startup and cached in memory.

---

## 4. Network Security

### 4.1 Kubernetes NetworkPolicy

Default deny-all ingress and egress policies are applied to the agent namespace. Explicit allow rules:

```yaml
# Ingress: Only from ingress controller
- from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
  ports:
    - port: 8000  # API
    - port: 3000  # Dashboard

# Egress: Only to required destinations
- to:
    - namespaceSelector: {}  # PostgreSQL, Redis within cluster
  ports:
    - port: 5432  # PostgreSQL
    - port: 6379  # Redis
- to:
    - ipBlock:
        cidr: 0.0.0.0/0  # External APIs (SIEM, TI)
  ports:
    - port: 443   # HTTPS
    - port: 8089  # Splunk REST API
```

### 4.2 Mutual TLS (mTLS)

When a service mesh (Istio or Linkerd) is deployed, mTLS is enforced for all pod-to-pod communication. This provides:

- Identity verification between services
- Encrypted communication even within the cluster network
- Protection against pod impersonation

### 4.3 Web Application Firewall (WAF)

WAF rules are configured on the ingress load balancer to protect against:

- SQL injection attempts
- Cross-site scripting (XSS)
- Path traversal attacks
- Request size limits (max body: 10 MB)
- Rate limiting: 100 requests per second per IP

---

## 5. Secret Management

### 5.1 Supported Secret Managers

| Secret Manager | Use Case | Configuration |
|---------------|----------|---------------|
| HashiCorp Vault | Multi-cloud, self-hosted | `VAULT_ADDR`, `VAULT_TOKEN` or Kubernetes auth |
| AWS Secrets Manager | AWS deployments | IAM role on EKS node group |
| Azure Key Vault | Azure deployments | Managed identity on AKS |
| GCP Secret Manager | GCP deployments | Workload identity on GKE |
| Kubernetes Secrets | Fallback (not recommended for production) | Mounted as environment variables |

### 5.2 Secrets Inventory

| Secret | Storage Location | Rotation Frequency |
|--------|-----------------|-------------------|
| JWT RSA private key | Vault/KMS | Quarterly |
| PostgreSQL credentials | Vault/KMS | Monthly |
| Redis password | Vault/KMS | Monthly |
| SIEM API keys/tokens | Vault/KMS | Per SIEM policy |
| VirusTotal API key | Vault/KMS | Annually |
| AbuseIPDB API key | Vault/KMS | Annually |
| CrowdStrike OAuth credentials | Vault/KMS | Quarterly |
| MISP API key | Vault/KMS | Per MISP policy |
| PagerDuty integration key | Vault/KMS | Annually |
| OAuth client secret (if applicable) | Vault/KMS | Quarterly |

### 5.3 Secret Rotation

The agent supports zero-downtime secret rotation:

1. New secret is created in the secret manager.
2. Agent is signaled to reload configuration (via SIGHUP or rolling restart).
3. Agent validates the new secret by making a test API call.
4. If validation succeeds, the new secret is used for all subsequent requests.
5. The old secret is marked for deletion after a configurable grace period (default: 24 hours).

---

## 6. Audit Logging

Every API call is logged with the following fields:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 UTC timestamp |
| `request_id` | Unique UUID for the request |
| `user_id` | Authenticated user UUID (or `system` for service accounts) |
| `user_role` | Role of the authenticated user |
| `source_ip` | Client IP address (from X-Forwarded-For if behind proxy) |
| `method` | HTTP method (GET, POST, PATCH, DELETE) |
| `path` | Request URI path |
| `status_code` | HTTP response status code |
| `action` | Semantic action name (e.g., `alert.view`, `incident.close`, `containment.approve`) |
| `resource_type` | Type of resource accessed (e.g., `alert`, `incident`, `user`) |
| `resource_id` | ID of the specific resource |
| `duration_ms` | Request processing time in milliseconds |
| `result` | `success` or `failure` |
| `failure_reason` | Reason for failure (if applicable) |

**Storage:** Audit logs are written to both structured log output (stdout, consumed by cluster log aggregator) and a dedicated `audit_logs` PostgreSQL table.

**Retention:** Audit logs are retained for 2 years in cold storage (S3/Blob) and 90 days in hot storage (PostgreSQL).

**Tamper Protection:** Audit log records are append-only. The `audit_logs` table is protected by a PostgreSQL trigger that prevents UPDATE and DELETE operations. The database user for the application has no `DELETE` or `TRUNCATE` privilege on this table.

**Alerting:** Failed authentication attempts exceeding 5 per minute from the same IP trigger a PagerDuty alert and temporary IP block (15-minute cooldown).
