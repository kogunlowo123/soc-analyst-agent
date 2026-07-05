# SOC Analyst Agent — API Reference

## Base URL

| Environment | URL |
|-------------|-----|
| Local | `http://localhost:8000` |
| Staging | `https://soc-analyst-agent.staging.example.com` |
| Production | `https://soc-analyst-agent.example.com` |

## Authentication

All endpoints except `/health` and `/docs` require authentication.

### Bearer Token (JWT)

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key

```http
X-API-Key: ska_live_abc123def456...
```

## Rate Limits

| Tier | Requests/minute | Burst |
|------|----------------|-------|
| Free | 60 | 10 |
| Standard | 300 | 50 |
| Enterprise | 1000 | 200 |

Rate limit headers are included in every response:

```http
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 287
X-RateLimit-Reset: 1720000000
```

---

## Endpoints

### Health Check

```http
GET /health
```

No authentication required.

**Response 200:**

```json
{
  "status": "healthy",
  "agent": "soc-analyst-agent",
  "version": "1.0.0",
  "uptime_seconds": 86400.5,
  "features": ["alert_triage", "ioc_enrichment", "event_correlation", "playbook_generation", "incident_reporting"],
  "dependencies": {
    "database": "healthy",
    "redis": "healthy",
    "opensearch": "healthy",
    "siem": "healthy"
  }
}
```

---

### Alert Triage

```http
POST /api/v1/alerts/triage
Content-Type: application/json
Authorization: Bearer <token>
```

Triage a security alert to determine if it is a true positive, false positive, or requires further investigation.

**Request Body:**

```json
{
  "alert_id": "ALERT-2024-001234",
  "alert_data": {
    "source": "splunk",
    "rule_name": "Suspicious PowerShell Execution",
    "severity": "high",
    "timestamp": "2024-12-15T14:30:00Z",
    "source_ip": "10.0.5.42",
    "destination_ip": "203.0.113.50",
    "user": "jdoe@example.com",
    "host": "WORKSTATION-42",
    "raw_log": "powershell.exe -enc SQBFAFgAIAAoA..."
  }
}
```

**Response 200:**

```json
{
  "alert_id": "ALERT-2024-001234",
  "verdict": "true_positive",
  "confidence": 0.92,
  "mitre_tactic": "Execution",
  "mitre_technique": "T1059.001",
  "mitre_technique_name": "PowerShell",
  "severity_assessment": "high",
  "recommended_action": "escalate",
  "reasoning": "Encoded PowerShell command detected from a user workstation communicating with a known C2 IP address. The base64-decoded command attempts to download and execute a remote script.",
  "evidence": [
    "Base64-encoded PowerShell execution (T1059.001)",
    "Destination IP 203.0.113.50 flagged as C2 in threat intelligence",
    "User jdoe has no history of PowerShell usage"
  ],
  "next_steps": [
    "Isolate host WORKSTATION-42 from the network",
    "Check for persistence mechanisms on the host",
    "Review jdoe's account for unauthorized access",
    "Query SIEM for other connections to 203.0.113.50"
  ]
}
```

**Response 422 (Validation Error):**

```json
{
  "detail": [
    {
      "loc": ["body", "alert_id"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

### IOC Enrichment

```http
POST /api/v1/ioc/enrich
Content-Type: application/json
Authorization: Bearer <token>
```

Enrich an indicator of compromise with threat intelligence from multiple sources.

**Request Body:**

```json
{
  "indicator": "203.0.113.50",
  "indicator_type": "ipv4"
}
```

Supported indicator types: `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `email`

**Response 200:**

```json
{
  "indicator": "203.0.113.50",
  "indicator_type": "ipv4",
  "reputation": "malicious",
  "threat_score": 95.0,
  "sources": [
    {
      "source": "virustotal",
      "score": 12,
      "total_engines": 87,
      "detections": ["Malware", "C2", "Botnet"],
      "last_analysis_date": "2024-12-14T00:00:00Z"
    },
    {
      "source": "abuseipdb",
      "confidence_score": 100,
      "total_reports": 342,
      "last_reported": "2024-12-15T12:00:00Z",
      "categories": ["SSH Brute Force", "Web Attack", "Botnet C2"]
    },
    {
      "source": "misp",
      "events": 5,
      "tags": ["apt28", "fancy-bear", "russia"],
      "first_seen": "2024-06-01T00:00:00Z"
    }
  ],
  "related_campaigns": ["APT28", "FancyBear-2024-Q4"],
  "geolocation": {
    "country": "RU",
    "city": "Moscow",
    "asn": "AS12345",
    "organization": "Example ISP"
  },
  "whois": {
    "registrar": "Example Registrar",
    "registered_date": "2023-01-15",
    "registrant_country": "RU"
  }
}
```

---

### Event Correlation

```http
POST /api/v1/events/correlate
Content-Type: application/json
Authorization: Bearer <token>
```

Correlate security events across multiple SIEM data sources within a time window.

**Request Body:**

```json
{
  "query": "All events related to user jdoe in the last 4 hours",
  "time_range": "4h",
  "data_sources": ["splunk", "sentinel", "crowdstrike"]
}
```

**Response 200:**

```json
{
  "correlation_id": "CORR-2024-005678",
  "events_found": 47,
  "time_range": "4h",
  "data_sources_queried": ["splunk", "sentinel", "crowdstrike"],
  "event_clusters": [
    {
      "cluster_name": "Suspicious Authentication",
      "event_count": 12,
      "timeframe": "14:00-14:15",
      "description": "Multiple failed logins followed by successful auth from unusual location",
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1078"
    },
    {
      "cluster_name": "PowerShell Execution",
      "event_count": 3,
      "timeframe": "14:20-14:25",
      "description": "Encoded PowerShell commands executed on workstation",
      "mitre_tactic": "Execution",
      "mitre_technique": "T1059.001"
    }
  ],
  "attack_chain": "Initial Access → Execution → C2 Communication",
  "risk_score": 87
}
```

---

### SIEM Query

```http
POST /api/v1/siem/query
Content-Type: application/json
Authorization: Bearer <token>
```

Execute a query against the connected SIEM platform. Accepts natural language or native query syntax.

**Request Body:**

```json
{
  "query": "Show me all failed RDP logins in the last 24 hours from external IPs",
  "index": "windows-security-*",
  "time_range": "24h"
}
```

**Response 200:**

```json
{
  "query_executed": "source=windows-security EventCode=4625 LogonType=10 | where NOT cidrmatch(\"10.0.0.0/8\", src_ip)",
  "query_language": "SPL",
  "total_results": 234,
  "results": [
    {
      "timestamp": "2024-12-15T14:30:00Z",
      "source_ip": "198.51.100.23",
      "target_host": "RDP-GW-01",
      "target_user": "admin",
      "event_code": 4625,
      "failure_reason": "Unknown user name or bad password"
    }
  ],
  "summary": "234 failed RDP logins detected from 18 unique external IPs targeting 3 hosts. Top targeted accounts: admin (89), administrator (67), svc_backup (34)."
}
```

---

### Investigation Playbook

```http
POST /api/v1/investigation/generate
Content-Type: application/json
Authorization: Bearer <token>
```

Generate a step-by-step investigation playbook for a specific alert type.

**Request Body:**

```json
{
  "alert_type": "suspicious_powershell_execution",
  "context": {
    "host": "WORKSTATION-42",
    "user": "jdoe@example.com",
    "command": "powershell.exe -enc SQBFAFgA..."
  }
}
```

**Response 200:**

```json
{
  "playbook_id": "PB-2024-001",
  "alert_type": "suspicious_powershell_execution",
  "steps": [
    {
      "step": 1,
      "action": "Decode the base64-encoded PowerShell command",
      "command": "echo 'SQBFAFgA...' | base64 -d",
      "expected_output": "IEX (New-Object Net.WebClient).DownloadString('http://...')",
      "risk_if_skipped": "Cannot assess payload intent"
    },
    {
      "step": 2,
      "action": "Query SIEM for process tree on WORKSTATION-42",
      "command": "index=sysmon host=WORKSTATION-42 EventCode=1 | search ParentCommandLine=*powershell*",
      "expected_output": "Process tree showing parent and child processes",
      "risk_if_skipped": "May miss lateral movement"
    },
    {
      "step": 3,
      "action": "Check for network connections from WORKSTATION-42 to external IPs",
      "command": "index=firewall src_ip=10.0.5.42 action=allowed dest_port!=443 dest_port!=80",
      "expected_output": "List of unusual outbound connections",
      "risk_if_skipped": "May miss C2 communication"
    }
  ],
  "estimated_duration_minutes": 45,
  "required_tools": ["SIEM", "EDR", "Threat Intel", "Network Logs"],
  "escalation_criteria": "Escalate to SOC Tier 2 if C2 communication is confirmed or if multiple hosts are affected"
}
```

---

### Incident Report

```http
POST /api/v1/incidents/report
Content-Type: application/json
Authorization: Bearer <token>
```

Create a structured incident summary report from investigation findings.

**Request Body:**

```json
{
  "alert_ids": ["ALERT-2024-001234", "ALERT-2024-001235"],
  "findings": {
    "root_cause": "Credential compromise via phishing email",
    "attack_vector": "Spear phishing with malicious attachment",
    "affected_hosts": ["WORKSTATION-42", "WORKSTATION-43"],
    "affected_users": ["jdoe@example.com"],
    "data_accessed": "No confirmed data exfiltration",
    "containment_actions": ["Isolated WORKSTATION-42", "Reset jdoe credentials"]
  },
  "severity": "high"
}
```

**Response 200:**

```json
{
  "incident_id": "INC-2024-000789",
  "severity": "high",
  "status": "contained",
  "summary": "A spear-phishing email delivered a malicious attachment to jdoe@example.com, resulting in encoded PowerShell execution on WORKSTATION-42 with C2 communication to a known APT28 IP address. The host was isolated within 15 minutes of detection. No data exfiltration was confirmed.",
  "timeline": [
    {"time": "2024-12-15T14:00:00Z", "event": "Phishing email received by jdoe"},
    {"time": "2024-12-15T14:25:00Z", "event": "Malicious attachment opened"},
    {"time": "2024-12-15T14:26:00Z", "event": "Encoded PowerShell execution detected"},
    {"time": "2024-12-15T14:30:00Z", "event": "SIEM alert triggered"},
    {"time": "2024-12-15T14:35:00Z", "event": "SOC Analyst Agent triaged alert as true positive"},
    {"time": "2024-12-15T14:40:00Z", "event": "Host WORKSTATION-42 isolated from network"}
  ],
  "mitre_mapping": {
    "tactics": ["Initial Access", "Execution", "Command and Control"],
    "techniques": ["T1566.001", "T1059.001", "T1071.001"]
  },
  "recommendations": [
    "Conduct organization-wide phishing awareness training",
    "Block the C2 IP 203.0.113.50 at the perimeter firewall",
    "Enable PowerShell Constrained Language Mode on all workstations",
    "Deploy application whitelisting on high-value targets"
  ],
  "created_at": "2024-12-15T15:00:00Z"
}
```

---

## Error Responses

All errors follow RFC 7807 Problem Details format:

```json
{
  "type": "https://soc-analyst-agent.example.com/errors/rate-limited",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "You have exceeded the rate limit of 300 requests per minute. Retry after 45 seconds.",
  "instance": "/api/v1/alerts/triage",
  "retry_after": 45
}
```

### Standard Error Codes

| Status | Type | Description |
|--------|------|-------------|
| 400 | `bad-request` | Invalid request body or parameters |
| 401 | `unauthorized` | Missing or invalid authentication |
| 403 | `forbidden` | Insufficient permissions for this operation |
| 404 | `not-found` | Resource not found |
| 409 | `conflict` | Resource conflict (duplicate alert ID) |
| 422 | `validation-error` | Request body fails schema validation |
| 429 | `rate-limited` | Rate limit exceeded |
| 500 | `internal-error` | Unexpected server error |
| 502 | `upstream-error` | SIEM or threat intel API unavailable |
| 503 | `service-unavailable` | Agent is starting up or shutting down |

---

## Webhook Events

The agent can send webhook notifications for completed analyses:

```json
{
  "event_type": "alert.triaged",
  "timestamp": "2024-12-15T14:35:00Z",
  "data": {
    "alert_id": "ALERT-2024-001234",
    "verdict": "true_positive",
    "severity": "high",
    "recommended_action": "escalate"
  }
}
```

Supported event types: `alert.triaged`, `ioc.enriched`, `incident.created`, `playbook.generated`

Configure webhook URL via `WEBHOOK_URL` environment variable.
