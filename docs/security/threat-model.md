# Threat Model

**Last Updated:** 2026-06-28
**Version:** 1.0
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

---

## 1. System Overview

The SOC Analyst Agent is a security-sensitive application that processes alert data from SIEM platforms, enriches it with threat intelligence, and provides investigation workflows. It has a broad attack surface due to its integrations with multiple external systems.

### 1.1 Trust Boundaries

```
+----------------------------------------------------------+
| External Network (Internet)                               |
|  [SOC Analysts via Browser]  [SOAR Platforms]             |
+---------------------------+------------------------------+
                            |
                     [WAF / Load Balancer]
                            |
+---------------------------+------------------------------+
| DMZ / Ingress Zone                                        |
|  [Ingress Controller]                                     |
+---------------------------+------------------------------+
                            |
+---------------------------+------------------------------+
| Agent Namespace (Trust Zone 1)                            |
|  [API Server]  [Dashboard]  [SIEM Connectors]             |
|  [Celery Workers]  [Enrichment Service]                   |
+----+----------+-----------+----------+-------------------+
     |          |           |          |
     v          v           v          v
  [PostgreSQL] [Redis]   [SIEM APIs]  [TI APIs]
  (Trust Zone 2)         (Trust Zone 3 - External)
```

### 1.2 Assets

| Asset | Sensitivity | Description |
|-------|------------|-------------|
| Alert data | High | Security alerts from SIEM containing potential evidence of attacks |
| Investigation notes | High | Analyst findings, hypotheses, and conclusions |
| IOC enrichment data | Medium | Reputation data from TI sources |
| SIEM credentials | Critical | API keys/tokens granting access to SIEM platforms |
| TI API keys | High | API keys for VirusTotal, AbuseIPDB, CrowdStrike, MISP |
| User credentials | Critical | JWT signing keys, OAuth secrets, password hashes |
| Audit logs | High | Record of all actions taken in the system |
| Containment actions | Critical | Ability to isolate endpoints via CrowdStrike |

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing

#### T-S1: JWT Token Forgery

**Threat:** An attacker crafts a valid-looking JWT token to impersonate an authorized user.

**Attack Vector:** Exploit weak key management, steal the JWT signing key, or exploit algorithm confusion (e.g., forcing HS256 when RS256 is expected).

**Impact:** Full access to the API with the permissions of the spoofed user.

**Mitigations:**
- RS256 signing with 4096-bit RSA keys (asymmetric; public key cannot be used to forge tokens)
- JWT library configured to reject tokens with `alg: none` or `alg: HS256`
- `kid` (key ID) header is validated against the server's key store
- Token expiration enforced (1 hour for access tokens)
- JTI (JWT ID) claim prevents token replay after revocation

**Residual Risk:** Low. Key compromise would require breaching the secret manager.

#### T-S2: SIEM API Credential Theft

**Threat:** An attacker extracts SIEM API credentials from the agent to access the SIEM directly.

**Attack Vector:** Container escape, environment variable exposure, or memory dump of the agent process.

**Impact:** Direct access to SIEM with the agent's permissions (read alerts, run searches, potentially modify detection rules).

**Mitigations:**
- Credentials stored in secret manager, not in environment variables or config files
- Credentials loaded into memory at startup and not written to disk
- Container images scanned for exposed secrets in CI/CD
- Kubernetes Pod Security Standards enforced (restricted profile)
- Runtime security monitoring (Falco) detects suspicious process activity in agent pods

**Residual Risk:** Medium. A container escape vulnerability could expose in-memory credentials.

#### T-S3: OAuth Session Hijacking

**Threat:** An attacker steals a valid session cookie to impersonate a logged-in analyst.

**Attack Vector:** XSS, network sniffing (if TLS is misconfigured), or physical access to an unlocked workstation.

**Mitigations:**
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- TLS 1.3 enforced for all connections
- CSP headers prevent XSS
- 30-minute idle session timeout
- Session bound to IP address (configurable, disabled by default for VPN users)

**Residual Risk:** Low.

---

### 2.2 Tampering

#### T-T1: Alert Data Manipulation

**Threat:** An attacker modifies alert data in transit between the SIEM and the agent to hide evidence of an attack or create false alerts.

**Attack Vector:** Man-in-the-middle on the network path between the agent and the SIEM API.

**Impact:** Analysts may miss real attacks or waste time investigating fabricated alerts.

**Mitigations:**
- TLS 1.2+ enforced for all SIEM API connections
- Certificate validation enabled (`verify=True` in HTTP clients)
- mTLS between pods within the cluster (via service mesh)
- Alert checksums computed at ingestion and verified before processing

**Residual Risk:** Low. Requires compromising the network or a valid TLS certificate.

#### T-T2: Investigation Note Tampering

**Threat:** An attacker modifies investigation notes in the database to alter the record of an investigation.

**Attack Vector:** SQL injection, compromised database credentials, or direct database access.

**Mitigations:**
- Parameterized queries via SQLAlchemy ORM (no raw SQL concatenation)
- Database user has minimal required permissions
- Investigation note history is append-only (edits create new versions, previous versions are retained)
- Audit log records all note modifications with user, timestamp, and diff

**Residual Risk:** Low.

#### T-T3: Prompt Injection via Alert Content

**Threat:** A malicious actor crafts alert content (e.g., log messages, email subjects) that contains prompt injection payloads designed to manipulate the agent's NLP-based classification or any LLM-powered analysis.

**Attack Vector:** Attacker plants crafted strings in systems that generate logs consumed by the SIEM, which then flow as alert data into the agent.

**Impact:** Misclassification of alerts, incorrect MITRE ATT&CK mappings, or bypassing of priority escalation.

**Mitigations:**
- Alert content is treated as untrusted data throughout the pipeline
- NLP classification uses structured feature extraction, not raw text prompting
- If LLM integration is enabled, alert content is sanitized (control characters stripped, length truncated to 4096 characters) before inclusion in any prompt
- LLM outputs are validated against expected schemas before being persisted
- Classification overrides are logged and reviewed

**Residual Risk:** Medium. Novel prompt injection techniques may bypass sanitization.

---

### 2.3 Repudiation

#### T-R1: Containment Action Denial

**Threat:** A user approves a containment action (endpoint isolation) and later denies having done so.

**Attack Vector:** Social engineering or claims of account compromise.

**Mitigations:**
- All containment approvals are logged in the audit log with user ID, timestamp, source IP, and session ID
- Containment approval requires explicit confirmation (two-step: request + confirm)
- Audit logs are append-only and tamper-protected at the database level
- PagerDuty notification is sent when containment is approved, creating an external record

**Residual Risk:** Low. The audit trail provides non-repudiation.

#### T-R2: Alert Status Change Without Accountability

**Threat:** An analyst marks a critical alert as a false positive without proper investigation, and there is no record of who made the change.

**Mitigations:**
- Every alert status change is logged with user, previous status, new status, and optional justification
- Status changes to `false_positive` or `closed` require a comment (enforced by API validation)
- Weekly reports highlight alerts closed without investigation notes

**Residual Risk:** Low.

---

### 2.4 Information Disclosure

#### T-I1: Data Exfiltration via API

**Threat:** An attacker with valid credentials (compromised account or malicious insider) exports large volumes of alert and investigation data.

**Attack Vector:** Bulk API queries, data export endpoints, or pagination abuse.

**Mitigations:**
- Export endpoints restricted to `soc_manager` and `admin` roles
- Export requests are rate-limited (max 1 export per minute, max 10,000 records per export)
- All export actions are logged in the audit log
- Anomaly detection on API usage patterns (alert on >100 requests/minute from a single user)
- Data Loss Prevention (DLP) headers on API responses (`Cache-Control: no-store`)

**Residual Risk:** Medium. A compromised `soc_manager` account could export data within rate limits.

#### T-I2: Credential Exposure in Logs

**Threat:** SIEM credentials, API keys, or JWT tokens are accidentally logged in application logs.

**Mitigations:**
- Structured logging with explicit field allowlists (credentials are never included in log context)
- Log sanitization filter replaces patterns matching API keys, tokens, and passwords with `[REDACTED]`
- CI/CD pipeline includes a log output scan that fails the build if credential patterns are detected
- Production logs are written to a restricted log aggregator with RBAC

**Residual Risk:** Low.

#### T-I3: Error Message Information Leakage

**Threat:** Detailed error messages (stack traces, database errors, internal paths) are exposed to API consumers.

**Mitigations:**
- Production error responses return generic messages with a correlation ID (e.g., `{"error": "Internal server error", "request_id": "abc-123"}`)
- Stack traces are logged server-side only
- Debug mode is disabled in production (`DEBUG=false`)
- Database error details are never forwarded to the client

**Residual Risk:** Low.

---

### 2.5 Denial of Service

#### T-D1: Alert Flood

**Threat:** An attacker generates a massive volume of false alerts in the SIEM to overwhelm the agent's processing pipeline.

**Attack Vector:** Compromised log source generating high-volume fake events that trigger detection rules.

**Impact:** Alert backlog grows, legitimate alerts are delayed, and the agent may run out of memory or disk space.

**Mitigations:**
- Alert deduplication using bloom filters in Redis (identical alerts within a 5-minute window are merged)
- Celery worker queue depth is monitored; alerts at >80% capacity trigger autoscaling
- Circuit breaker pattern: if alert ingestion exceeds 2,000/minute for 5 consecutive minutes, new alerts are sampled (1 in 10) and a critical alert is sent to the SOC
- PostgreSQL connection pool limits prevent database exhaustion
- Redis memory limit with `allkeys-lru` eviction prevents OOM

**Residual Risk:** Medium. A sustained flood could still degrade performance.

#### T-D2: API Rate Abuse

**Threat:** An attacker or misbehaving client sends excessive API requests to exhaust server resources.

**Mitigations:**
- Rate limiting at WAF/ingress: 100 requests/second per IP
- Application-level rate limiting: 30 requests/second per authenticated user
- Request body size limit: 10 MB
- Query timeout: 30 seconds
- Connection limits: max 100 concurrent connections per user

**Residual Risk:** Low.

---

### 2.6 Elevation of Privilege

#### T-E1: Role Escalation via API Manipulation

**Threat:** An analyst modifies their JWT token claims or API requests to gain `soc_lead` or `admin` privileges.

**Mitigations:**
- JWT tokens are signed with RS256; the private key is not accessible to clients
- Role claims in the JWT are set by the server at token issuance and cannot be modified by the client
- API endpoints validate roles by decoding the JWT with the server's public key
- Role changes require admin action through a separate user management endpoint

**Residual Risk:** Low.

#### T-E2: Container Escape

**Threat:** An attacker exploits a vulnerability in the container runtime to escape the agent container and access the host or other pods.

**Mitigations:**
- Pods run as non-root user (`runAsNonRoot: true`, `runAsUser: 65534`)
- Read-only root filesystem (`readOnlyRootFilesystem: true`)
- No privileged containers (`privileged: false`)
- Capabilities dropped (`drop: ["ALL"]`)
- seccomp profile: `RuntimeDefault`
- AppArmor profile: `runtime/default`
- Pod Security Standards: `restricted` profile enforced at namespace level
- Container images rebuilt weekly with latest base image patches

**Residual Risk:** Low. Requires a zero-day in the container runtime.

#### T-E3: Database Privilege Escalation

**Threat:** The agent's database user is granted excessive permissions, allowing an attacker who gains database access to modify schema, create new users, or access other databases.

**Mitigations:**
- Database user has `SELECT`, `INSERT`, `UPDATE` on application tables only
- No `DELETE` on `audit_logs` table
- No `CREATE ROLE`, `ALTER SYSTEM`, or `SUPERUSER` privileges
- Schema migrations run under a separate migration user with `CREATE TABLE` and `ALTER TABLE` privileges, invoked only during deployment
- Database connections from the application use SSL with certificate verification

**Residual Risk:** Low.

---

## 3. Threat Summary Matrix

| ID | Threat | Category | Likelihood | Impact | Risk Level | Mitigated |
|----|--------|----------|------------|--------|------------|-----------|
| T-S1 | JWT Token Forgery | Spoofing | Low | Critical | Medium | Yes |
| T-S2 | SIEM Credential Theft | Spoofing | Medium | Critical | High | Yes |
| T-S3 | OAuth Session Hijacking | Spoofing | Low | High | Medium | Yes |
| T-T1 | Alert Data Manipulation | Tampering | Low | High | Medium | Yes |
| T-T2 | Investigation Note Tampering | Tampering | Low | Medium | Low | Yes |
| T-T3 | Prompt Injection | Tampering | Medium | Medium | Medium | Partial |
| T-R1 | Containment Action Denial | Repudiation | Low | High | Medium | Yes |
| T-R2 | Alert Status Change Without Accountability | Repudiation | Medium | Medium | Medium | Yes |
| T-I1 | Data Exfiltration via API | Info Disclosure | Medium | High | High | Partial |
| T-I2 | Credential Exposure in Logs | Info Disclosure | Low | Critical | Medium | Yes |
| T-I3 | Error Message Leakage | Info Disclosure | Low | Low | Low | Yes |
| T-D1 | Alert Flood | DoS | Medium | High | High | Partial |
| T-D2 | API Rate Abuse | DoS | Medium | Medium | Medium | Yes |
| T-E1 | Role Escalation | EoP | Low | Critical | Medium | Yes |
| T-E2 | Container Escape | EoP | Low | Critical | Medium | Yes |
| T-E3 | Database Privilege Escalation | EoP | Low | High | Medium | Yes |

---

## 4. Review Schedule

This threat model should be reviewed:

- Quarterly (minimum)
- After any security incident involving the agent
- After adding new integrations or features
- After significant infrastructure changes
- After a penetration test or security audit
