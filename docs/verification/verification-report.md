# External API Verification Report

**Verification Date:** 2026-06-28
**Tester:** SOC Platform Engineering Team
**Environment:** Staging (pre-production)
**Report Version:** 1.0

---

## 1. Splunk REST API

| Field | Detail |
|-------|--------|
| **API Version** | v9.1 (Splunk Enterprise 9.1.x / Splunk Cloud) |
| **Auth Method** | Bearer token (Splunk authentication tokens) or Basic Auth (username/password). Token-based auth is recommended for service accounts. |
| **Rate Limits** | No hard rate limit enforced by default; governed by `max_searches_per_cpu` and `max_rt_searches_per_cpu` in `limits.conf`. Recommended: cap at 200 concurrent searches. |
| **Quotas** | Search quota governed by role-based `srchDiskQuota` (default 100 MB) and `srchJobsQuota` (default 10 concurrent). Adjust for agent service account. |
| **Tested Endpoints** | `POST /services/search/jobs` (create search), `GET /services/search/jobs/{search_id}/results` (fetch results), `GET /services/search/jobs/{search_id}` (job status), `GET /services/saved/searches` (list saved searches), `POST /services/receivers/simple` (ingest events) |
| **Verification Result** | PASS |
| **Notes** | Search jobs with `exec_mode=oneshot` return results inline for queries under 10,000 events. For larger result sets, use `exec_mode=normal` and poll for completion. Output mode set to `output_mode=json`. XML responses deprecated for agent consumption. |

## 2. Elastic Security API

| Field | Detail |
|-------|--------|
| **API Version** | 8.14 (Elasticsearch / Elastic Security 8.x) |
| **Auth Method** | API key (recommended) or Basic Auth. API keys created via `POST /_security/api_key` with role restrictions. |
| **Rate Limits** | No built-in rate limit; governed by cluster thread pool capacity. Circuit breaker triggers at 95% JVM heap. Recommended: max 50 concurrent bulk requests. |
| **Quotas** | Index lifecycle policies govern retention. Detection rules limited to 1,000 per Kibana space by default. |
| **Tested Endpoints** | `GET /api/detection_engine/rules/_find` (list detection rules), `POST /api/detection_engine/signals/search` (search alerts), `PATCH /api/detection_engine/signals/status` (update alert status), `GET /api/timeline` (get timelines), `POST /api/detection_engine/rules` (create rule), `GET /api/detection_engine/rules/prepackaged/_status` (prebuilt rules status) |
| **Verification Result** | PASS |
| **Notes** | Alert search uses KQL or EQL syntax. Pagination via `page` and `per_page` query parameters, max 10,000 results. The `signal.status` field accepts `open`, `acknowledged`, `closed`. Bulk status updates limited to 100 alerts per request. |

## 3. Microsoft Sentinel API

| Field | Detail |
|-------|--------|
| **API Version** | 2023-11-01 (Azure Resource Manager) |
| **Auth Method** | OAuth 2.0 via Azure AD (now Microsoft Entra ID). Service principal with client credentials grant (`client_id`, `client_secret`, `tenant_id`). Requires `Microsoft Sentinel Responder` or `Microsoft Sentinel Reader` role. |
| **Rate Limits** | ARM throttling: 12,000 read requests per hour per subscription, 1,200 write requests per hour per subscription. Log Analytics query API: 200 requests per 30 seconds per workspace. |
| **Quotas** | Log Analytics workspace ingestion: up to 500 GB/day per workspace (configurable). Analytics rules limited to 512 per workspace. |
| **Tested Endpoints** | `GET /subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.SecurityInsights/incidents` (list incidents), `PATCH /...incidents/{incidentId}` (update incident), `GET /...incidents/{incidentId}/comments` (list comments), `POST /...incidents/{incidentId}/comments` (add comment), `GET /...alertRules` (list analytics rules), `POST /providers/Microsoft.OperationalInsights/workspaces/{workspace}/api/query` (run KQL query) |
| **Verification Result** | PASS |
| **Notes** | Incident severity values: `High`, `Medium`, `Low`, `Informational`. Status values: `New`, `Active`, `Closed`. Classification on close: `BenignPositive`, `FalsePositive`, `TruePositive`, `Undetermined`. Token refresh handled automatically via MSAL library. |

## 4. VirusTotal API v3

| Field | Detail |
|-------|--------|
| **API Version** | v3 |
| **Auth Method** | API key passed via `x-apikey` HTTP header. |
| **Rate Limits** | Free tier: 4 requests/minute, 500 requests/day, 15.5K requests/month. Premium tier: 30,000 requests/day (standard), higher tiers available. |
| **Quotas** | Free: 500 lookups/day. Premium: governed by license. File upload limit: 650 MB per file (32 MB for free tier). |
| **Tested Endpoints** | `GET /api/v3/files/{id}` (file report), `GET /api/v3/urls/{id}` (URL report), `GET /api/v3/ip_addresses/{ip}` (IP report), `GET /api/v3/domains/{domain}` (domain report), `POST /api/v3/files` (upload file for scan), `GET /api/v3/files/{id}/behaviours` (sandbox behavior) |
| **Verification Result** | PASS |
| **Notes** | Hash lookups (SHA-256, SHA-1, MD5) return detection results from 70+ AV engines. URL IDs must be base64url-encoded (without padding). Rate limit headers: `X-Api-Message` indicates quota status. Implement exponential backoff on 429 responses. Premium API key required for YARA ruleset searches and retrohunt. |

## 5. AbuseIPDB API v2

| Field | Detail |
|-------|--------|
| **API Version** | v2 |
| **Auth Method** | API key passed via `Key` HTTP header. |
| **Rate Limits** | Free tier: 1,000 requests/day (check endpoint), 5 reports/15 minutes. Standard: 5,000 checks/day. Premium: 50,000 checks/day. |
| **Quotas** | Check endpoint: 1,000/day (free), 5,000/day (standard), 50,000/day (premium). Report endpoint: 500 reports/day (free). Bulk check: available on premium only. |
| **Tested Endpoints** | `GET /api/v2/check` (check IP reputation), `POST /api/v2/report` (report IP), `GET /api/v2/blacklist` (get blacklist), `GET /api/v2/check-block` (check CIDR block) |
| **Verification Result** | PASS |
| **Notes** | Confidence score ranges 0-100. `maxAgeInDays` parameter recommended at 90 for operational relevance. Categories include 18 (brute-force), 14 (port scan), 21 (web attack), etc. The `check-block` endpoint supports up to /24 CIDR blocks on free tier. Response includes ISP, usage type, and country data. |

## 6. MISP REST API

| Field | Detail |
|-------|--------|
| **API Version** | MISP 2.4.x REST API (latest verified: 2.4.187) |
| **Auth Method** | API key passed via `Authorization` header. Key generated per user in MISP web interface. |
| **Rate Limits** | No built-in rate limiting. Governed by server capacity and Apache/Nginx configuration. Recommended: self-impose 100 requests/minute. |
| **Quotas** | No hard quotas. Event size limited by `upload_max_filesize` and `post_max_size` in PHP configuration (default 50 MB). |
| **Tested Endpoints** | `GET /events/index` (list events), `GET /events/view/{eventId}` (get event), `POST /events/restSearch` (search events), `GET /attributes/restSearch` (search attributes), `POST /events/add` (create event), `POST /sightings/add/{attributeId}` (add sighting) |
| **Verification Result** | PASS |
| **Notes** | Search supports extensive filters: `type`, `category`, `org`, `tags`, `timestamp`, `publish_timestamp`, `value`. Response format controlled by `Accept` header (`application/json`). PyMISP library (v2.4.187+) recommended for Python integration. Correlation engine may slow responses for large datasets; use `includeCorrelations=0` for performance. |

## 7. CrowdStrike Falcon API

| Field | Detail |
|-------|--------|
| **API Version** | Falcon API (OAuth2, versioned endpoints) |
| **Auth Method** | OAuth 2.0 client credentials. `POST /oauth2/token` with `client_id` and `client_secret` to obtain bearer token. Tokens expire after 30 minutes. |
| **Rate Limits** | Rate limits vary per endpoint. Detections: 100 requests/minute. Hosts: 100 requests/minute. IOC management: 300 requests/minute. Real Time Response: 10 sessions/minute. |
| **Quotas** | Custom IOC limit: 1,000,000 indicators per CID. RTR session limit: 10 concurrent sessions. Streaming API: 1 connection per data feed. |
| **Tested Endpoints** | `GET /detects/queries/detects/v1` (query detection IDs), `POST /detects/entities/summaries/GET/v1` (get detection details), `PATCH /detects/entities/detects/v2` (update detection status), `GET /devices/queries/devices/v1` (query hosts), `POST /devices/entities/devices/v2` (get host details), `POST /indicators/entities/iocs/v1` (create custom IOC), `POST /intel/combined/indicators/v1` (search threat intel) |
| **Verification Result** | PASS |
| **Notes** | Detection status values: `new`, `in_progress`, `true_positive`, `false_positive`, `closed`. Host containment via `POST /hosts/entities/host-actions/v2` with `action_name=contain`. FalconPy SDK (v1.4+) recommended for Python integration. Base URL varies by cloud: `api.crowdstrike.com` (US-1), `api.us-2.crowdstrike.com` (US-2), `api.eu-1.crowdstrike.com` (EU-1). |

---

## Verification Summary

| API | Version | Auth | Rate Limits Documented | Endpoints Verified | Status |
|-----|---------|------|------------------------|-------------------|--------|
| Splunk REST API | v9.1 | Bearer Token | Yes | 5 | PASS |
| Elastic Security API | 8.14 | API Key | Yes | 6 | PASS |
| Microsoft Sentinel API | 2023-11-01 | OAuth 2.0 | Yes | 6 | PASS |
| VirusTotal API | v3 | API Key | Yes | 6 | PASS |
| AbuseIPDB API | v2 | API Key | Yes | 4 | PASS |
| MISP REST API | 2.4.187 | API Key | N/A (self-managed) | 6 | PASS |
| CrowdStrike Falcon API | OAuth2 | OAuth 2.0 | Yes | 7 | PASS |

**Overall Verification Status:** ALL PASS

---

## Verification Methodology

1. Each API was tested against a dedicated staging instance or sandbox account.
2. Authentication was validated by obtaining tokens/keys and making authenticated requests.
3. Rate limits were tested by issuing bursts of requests and observing throttling behavior.
4. Error handling was verified for 400, 401, 403, 404, 429, and 500 response codes.
5. Response schemas were validated against documented specifications.
6. Pagination was tested for endpoints returning large result sets.
7. Timeout behavior was observed for long-running queries (Splunk searches, Sentinel KQL).
