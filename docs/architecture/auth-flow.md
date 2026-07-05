# Authentication Flow Architecture

## Overview

The SOC Analyst Agent implements a layered authentication architecture supporting JWT token-based authentication for human users (SOC analysts accessing the dashboard), API key validation for machine-to-machine integrations (SIEM webhooks, automated tooling), and OAuth2 authorization code flow for connecting to external SIEM platforms and third-party services.

## Authentication Architecture Diagram

```mermaid
graph TB
    subgraph Clients["Client Types"]
        browser["SOC Analyst Browser<br/>Next.js Dashboard<br/>OAuth2 PKCE Flow"]
        api_client["API Client<br/>Automation Scripts<br/>API Key Authentication"]
        siem_webhook["SIEM Webhook<br/>Splunk / Elastic<br/>HMAC-SHA256 Signature"]
        peer_agent["Peer Agent<br/>A2A Protocol<br/>mTLS Authentication"]
    end

    subgraph Auth_Layer["Authentication Layer"]
        auth_middleware["Auth Middleware<br/>FastAPI Depends<br/>Route-level enforcement"]
        jwt_validator["JWT Validator<br/>RS256 verification<br/>Issuer/audience check<br/>Expiry validation"]
        api_key_validator["API Key Validator<br/>SHA-256 hash lookup<br/>Scope verification<br/>Rate limit check"]
        webhook_validator["Webhook Validator<br/>HMAC-SHA256 signature<br/>Timestamp freshness<br/>Replay prevention"]
        mtls_validator["mTLS Validator<br/>X.509 cert chain<br/>CN/SAN validation<br/>Revocation check"]
    end

    subgraph Token_Service["Token Service"]
        token_issuer["Token Issuer<br/>RS256 JWT signing<br/>Access: 15 min TTL<br/>Refresh: 7 day TTL"]
        oauth2_handler["OAuth2 Handler<br/>Authorization Code + PKCE<br/>IdP: Okta / Azure AD"]
        session_store["Session Store<br/>Redis<br/>Refresh token tracking<br/>Revocation list"]
    end

    subgraph IdP["Identity Provider"]
        okta["Okta / Azure AD<br/>OIDC Provider<br/>SAML 2.0 Fallback<br/>MFA Enforcement"]
    end

    subgraph RBAC["Role-Based Access Control"]
        role_check["Role Evaluator<br/>Roles: soc_analyst,<br/>soc_manager, ir_lead,<br/>admin, readonly"]
        permission_check["Permission Check<br/>Resource-level ACL<br/>Investigation ownership<br/>Tenant isolation"]
    end

    browser -->|1. Login redirect| oauth2_handler
    oauth2_handler -->|2. Authorization request| okta
    okta -->|3. Auth code + PKCE| oauth2_handler
    oauth2_handler -->|4. Token exchange| okta
    okta -->|5. ID token + user info| oauth2_handler
    oauth2_handler -->|6. Issue JWT pair| token_issuer
    token_issuer -->|7. Store refresh token| session_store
    oauth2_handler -->|8. Return tokens| browser

    browser -->|Bearer JWT| auth_middleware
    api_client -->|X-API-Key header| auth_middleware
    siem_webhook -->|X-Webhook-Signature| auth_middleware
    peer_agent -->|Client certificate| auth_middleware

    auth_middleware --> jwt_validator
    auth_middleware --> api_key_validator
    auth_middleware --> webhook_validator
    auth_middleware --> mtls_validator

    jwt_validator --> role_check
    api_key_validator --> role_check
    webhook_validator --> role_check
    mtls_validator --> role_check
    role_check --> permission_check

    style Clients fill:#e8f5e9,stroke:#388e3c
    style Auth_Layer fill:#e3f2fd,stroke:#1565c0
    style Token_Service fill:#fff3e0,stroke:#f57c00
    style IdP fill:#f3e5f5,stroke:#7b1fa2
    style RBAC fill:#fce4ec,stroke:#c62828
```

## OAuth2 Authorization Code Flow with PKCE

```mermaid
sequenceDiagram
    participant Browser as SOC Analyst Browser
    participant Dashboard as Next.js Dashboard
    participant API as FastAPI API
    participant IdP as Okta / Azure AD
    participant Redis as Redis Session Store

    Note over Browser: Analyst navigates to SOC Dashboard

    Browser->>Dashboard: GET /login
    Dashboard->>Dashboard: Generate PKCE code_verifier (43-128 chars)<br/>Compute code_challenge = BASE64URL(SHA256(code_verifier))
    Dashboard->>Browser: 302 Redirect to IdP /authorize

    Browser->>IdP: GET /authorize?<br/>response_type=code&<br/>client_id=soc-agent-dashboard&<br/>redirect_uri=https://soc.example.com/callback&<br/>scope=openid profile email groups&<br/>state=random-csrf-state&<br/>code_challenge=BASE64URL(SHA256(verifier))&<br/>code_challenge_method=S256
    
    IdP->>Browser: Login page (username + password + MFA)
    Browser->>IdP: Credentials + MFA token
    IdP->>IdP: Validate credentials, enforce MFA
    IdP->>Browser: 302 Redirect to /callback?code=AUTH_CODE&state=random-csrf-state

    Browser->>Dashboard: GET /callback?code=AUTH_CODE&state=random-csrf-state
    Dashboard->>Dashboard: Validate state parameter (CSRF check)
    Dashboard->>API: POST /api/v1/auth/token {code: AUTH_CODE, code_verifier: VERIFIER}

    API->>IdP: POST /token {<br/>grant_type=authorization_code&<br/>code=AUTH_CODE&<br/>code_verifier=VERIFIER&<br/>client_id=soc-agent-dashboard&<br/>redirect_uri=https://soc.example.com/callback}
    IdP-->>API: 200 OK {id_token: "...", access_token: "...", refresh_token: "..."}

    API->>API: Validate ID token (RS256, issuer, audience, expiry)
    API->>API: Extract user claims (sub, email, groups)
    API->>API: Map IdP groups to SOC roles

    API->>API: Generate SOC JWT access token (RS256, 15 min TTL)
    API->>API: Generate SOC refresh token (opaque, 7 day TTL)
    API->>Redis: SETEX refresh_token:{jti} user_data (TTL: 604800s)

    API-->>Dashboard: 200 OK {access_token: "eyJ...", refresh_token: "ref_...", expires_in: 900}
    Dashboard->>Browser: Store tokens (httpOnly secure cookie for refresh, memory for access)

    Note over Browser: Subsequent API requests

    Browser->>API: GET /api/v1/alerts (Authorization: Bearer eyJ...)
    API->>API: Validate JWT (RS256, expiry, issuer)
    API->>API: Check role permissions
    API-->>Browser: 200 OK {alerts: [...]}

    Note over Browser: Access token expired (after 15 min)

    Browser->>API: POST /api/v1/auth/refresh (Cookie: refresh_token=ref_...)
    API->>Redis: GET refresh_token:{jti}
    Redis-->>API: user_data (exists, not revoked)
    API->>API: Generate new access token (15 min TTL)
    API->>API: Rotate refresh token (new jti, invalidate old)
    API->>Redis: DEL refresh_token:{old_jti}
    API->>Redis: SETEX refresh_token:{new_jti} user_data (TTL: 604800s)
    API-->>Browser: 200 OK {access_token: "eyJ..new..", refresh_token: "ref_new.."}
```

## JWT Token Structure

### Access Token Claims

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "soc-agent-signing-key-2026"
  },
  "payload": {
    "iss": "https://soc.example.com",
    "sub": "user:okta:00u1234567890",
    "aud": "soc-agent-api",
    "exp": 1751641200,
    "iat": 1751640300,
    "jti": "tok_a1b2c3d4e5f6",
    "email": "jdoe@example.com",
    "name": "Jane Doe",
    "role": "soc_analyst",
    "permissions": ["alerts:read", "alerts:triage", "investigations:read", "investigations:create", "playbooks:read"],
    "tenant_id": "tenant_001",
    "session_id": "sess_xyz789"
  }
}
```

### Role Definitions

| Role | Permissions | Use Case |
|------|-------------|----------|
| `soc_analyst` | `alerts:read`, `alerts:triage`, `investigations:read`, `investigations:create`, `playbooks:read` | Day-to-day alert triage and investigation |
| `soc_manager` | All analyst permissions + `alerts:configure`, `investigations:assign`, `reports:read`, `config:read`, `metrics:read` | SOC operations management |
| `ir_lead` | All manager permissions + `investigations:escalate`, `containment:approve`, `reports:create`, `config:write` | Incident response leadership |
| `admin` | All permissions + `users:manage`, `api_keys:manage`, `config:admin`, `audit:read` | System administration |
| `readonly` | `alerts:read`, `investigations:read`, `reports:read`, `metrics:read` | Auditors, compliance reviewers |
| `service` | Scoped per API key: specific resource + action combinations | Automated integrations |

## API Key Authentication

```mermaid
sequenceDiagram
    participant Client as API Client
    participant API as FastAPI API
    participant DB as PostgreSQL
    participant Redis as Redis Cache

    Client->>API: GET /api/v1/alerts<br/>X-API-Key: ska_live_a1b2c3d4e5f6g7h8i9j0

    API->>API: Extract API key from header
    API->>API: Compute SHA-256 hash of key

    API->>Redis: GET api_key_cache:{hash}
    alt Cache Hit
        Redis-->>API: {key_id, scopes, rate_limit, tenant_id}
    else Cache Miss
        API->>DB: SELECT * FROM api_keys WHERE key_hash = '{hash}' AND revoked = false AND expires_at > NOW()
        DB-->>API: {key_id, scopes, rate_limit, tenant_id, created_by}
        API->>Redis: SETEX api_key_cache:{hash} data (TTL: 300s)
    end

    API->>API: Check rate limit (sliding window)
    API->>Redis: INCR rate_limit:{key_id}:{window}
    
    alt Rate Limit OK
        API->>API: Validate scope covers requested resource
        API-->>Client: 200 OK {alerts: [...]}
    else Rate Limit Exceeded
        API-->>Client: 429 Too Many Requests<br/>Retry-After: 60
    end
```

### API Key Format

| Component | Format | Example |
|-----------|--------|---------|
| Prefix | `ska_` (SOC Key API) | `ska_` |
| Environment | `live_` or `test_` | `live_` |
| Key Body | 32 random alphanumeric chars | `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6` |
| Full Key | `{prefix}{env}{body}` | `ska_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6` |

### API Key Scopes

| Scope | Description | Allowed Operations |
|-------|-------------|-------------------|
| `alerts:ingest` | SIEM webhook alert ingestion | POST /api/v1/alerts/ingest |
| `alerts:read` | Read alert data | GET /api/v1/alerts/* |
| `investigations:read` | Read investigation data | GET /api/v1/investigations/* |
| `reports:read` | Download investigation reports | GET /api/v1/reports/* |
| `ioc:enrich` | IOC enrichment API access | POST /api/v1/ioc/enrich |
| `admin:full` | Full administrative access | All endpoints |

## SIEM Webhook Validation

```mermaid
sequenceDiagram
    participant SIEM as Splunk SIEM
    participant API as FastAPI API
    participant Validator as Webhook Validator

    SIEM->>API: POST /api/v1/alerts/ingest/splunk<br/>Content-Type: application/json<br/>X-Webhook-Signature: sha256=a1b2c3...<br/>X-Webhook-Timestamp: 1751640300<br/>X-Webhook-ID: wh_001<br/>{alert_payload}

    API->>Validator: Validate webhook request

    Validator->>Validator: 1. Check timestamp freshness<br/>(reject if > 300s old)
    Validator->>Validator: 2. Check replay prevention<br/>(Redis SET wh_id:{X-Webhook-ID}, NX, EX 600)
    Validator->>Validator: 3. Compute expected signature<br/>HMAC-SHA256(webhook_secret, timestamp + "." + body)
    Validator->>Validator: 4. Constant-time comparison<br/>of computed vs provided signature

    alt Validation Passes
        Validator-->>API: Valid
        API->>API: Process alert payload
        API-->>SIEM: 200 OK {status: "accepted", alert_id: "alert_001"}
    else Validation Fails
        Validator-->>API: Invalid (reason: timestamp_expired | replay_detected | signature_mismatch)
        API-->>SIEM: 401 Unauthorized {error: "Invalid webhook signature"}
        API->>API: Log security event (failed webhook validation)
    end
```

## OAuth2 SIEM Platform Authorization

```mermaid
sequenceDiagram
    participant Admin as SOC Admin
    participant API as FastAPI API
    participant Sentinel as Microsoft Sentinel
    participant SM as AWS Secrets Manager

    Note over Admin: Configure Sentinel SIEM integration

    Admin->>API: POST /api/v1/integrations/sentinel/connect
    API->>API: Generate state + PKCE verifier
    API-->>Admin: 302 Redirect to Azure AD /authorize?<br/>client_id=soc-agent-sentinel&<br/>scope=https://graph.microsoft.com/.default&<br/>response_type=code

    Admin->>Sentinel: Authorize SOC Agent access to Sentinel
    Sentinel-->>Admin: 302 Redirect with auth code

    Admin->>API: GET /api/v1/integrations/sentinel/callback?code=AUTH_CODE
    API->>Sentinel: POST /oauth2/v2.0/token<br/>{grant_type: authorization_code, code: AUTH_CODE, client_secret: ...}
    Sentinel-->>API: {access_token: "...", refresh_token: "...", expires_in: 3600}

    API->>SM: PutSecretValue("siem/sentinel/tokens", {access_token, refresh_token})
    SM-->>API: 200 OK {ARN: "arn:aws:secretsmanager:..."}

    API-->>Admin: 200 OK {status: "connected", integration: "sentinel"}

    Note over API: Token refresh (background Celery task)

    API->>SM: GetSecretValue("siem/sentinel/tokens")
    SM-->>API: {refresh_token: "..."}
    API->>Sentinel: POST /oauth2/v2.0/token<br/>{grant_type: refresh_token, refresh_token: "..."}
    Sentinel-->>API: {access_token: "new_...", refresh_token: "new_...", expires_in: 3600}
    API->>SM: PutSecretValue("siem/sentinel/tokens", {new tokens})
```

## Security Controls Summary

| Control | Implementation | Standard |
|---------|---------------|----------|
| Password Policy | Enforced by IdP (Okta/Azure AD): 12+ chars, complexity, no reuse | NIST SP 800-63B |
| Multi-Factor Authentication | Required for all human users via IdP (TOTP, WebAuthn, push) | NIST SP 800-63B AAL2 |
| Token Signing | RS256 (RSA 2048-bit key pair), rotated annually | RFC 7519 |
| Token Storage | Access token in memory only, refresh token in httpOnly secure cookie | OWASP |
| CSRF Protection | State parameter + PKCE for OAuth2, SameSite=Strict cookies | OWASP |
| API Key Hashing | SHA-256 (only hash stored in database, plaintext never persisted) | OWASP |
| Webhook Integrity | HMAC-SHA256 with shared secret, timestamp validation, replay prevention | Industry standard |
| mTLS | X.509 certificates from internal PKI, 90-day rotation | RFC 5246 |
| Session Management | Absolute timeout: 8 hours, idle timeout: 30 minutes, concurrent session limit: 3 | OWASP |
| Credential Storage | AWS Secrets Manager with KMS encryption, 30-day rotation | AWS Security Best Practices |
| Audit Logging | All authentication events logged with IP, user agent, outcome | SOC 2 Type II |
