# Sequence Diagrams

## Overview

This document contains detailed sequence diagrams for the four primary interaction flows of the SOC Analyst Agent: alert triage, IOC enrichment, incident escalation, and user chat interaction. Each diagram traces the complete message flow between components with protocols, ports, and data formats.

## 1. Alert Triage Flow

```mermaid
sequenceDiagram
    participant Splunk as Splunk SIEM<br/>(Port 8089)
    participant API as FastAPI API<br/>(Port 8000)
    participant Redis as Redis<br/>(Port 6379)
    participant Engine as Agent Engine<br/>(Port 50051)
    participant LLM as OpenAI GPT-4o<br/>(Port 443)
    participant PG as PostgreSQL<br/>(Port 5432)
    participant OS as OpenSearch<br/>(Port 9200)
    participant Slack as Slack API<br/>(Port 443)

    Note over Splunk,Slack: Alert Triage Flow - New Splunk Alert

    Splunk->>API: POST /api/v1/alerts/ingest/splunk<br/>Content-Type: application/json<br/>X-Webhook-Signature: sha256=abc123<br/>X-Webhook-Timestamp: 1751640300<br/>{rule_name, src_ip, dst_ip, raw_log, severity}

    API->>API: Validate HMAC-SHA256 webhook signature<br/>Check timestamp freshness (< 300s)
    API->>API: Normalize alert to unified schema<br/>Map Splunk fields to internal format

    API->>Redis: SET dedup:{sha256_hash} NX EX 900<br/>(15-min dedup window)
    Redis-->>API: OK (new alert) or nil (duplicate)

    alt Duplicate Alert
        API->>PG: UPDATE alerts SET sighting_count = sighting_count + 1<br/>WHERE dedup_hash = '{hash}'
        API-->>Splunk: 200 OK {status: "merged", alert_id: "existing_id"}
    else New Alert
        API->>PG: INSERT INTO alerts (alert_id, source, raw_payload, ...)<br/>VALUES (gen_random_uuid(), 'splunk', ...)
        PG-->>API: {alert_id: "alert_001"}

        API->>OS: POST /alerts-2026.07.04/_doc/alert_001<br/>{alert fields for full-text search}
        OS-->>API: 201 Created

        API->>Engine: gRPC TriageAlert(alert_id="alert_001")<br/>(Internal port 50051)

        Engine->>PG: SELECT * FROM alerts WHERE alert_id = 'alert_001'
        PG-->>Engine: {alert payload}

        Engine->>PG: SELECT * FROM suppression_rules WHERE active = true
        PG-->>Engine: [{pattern: "known_scanner_.*", action: "suppress"}, ...]

        Engine->>Engine: Evaluate suppression rules against alert fields

        alt Alert Suppressed
            Engine->>PG: UPDATE alerts SET status = 'suppressed',<br/>suppression_reason = 'Rule: known_scanner'<br/>WHERE alert_id = 'alert_001'
            Engine-->>API: TriageResult(status="suppressed")
        else Alert Not Suppressed
            Engine->>LLM: POST /v1/chat/completions<br/>Model: gpt-4o<br/>System: "Classify this security alert..."<br/>User: {normalized alert payload}<br/>Response_format: {severity: int, type: str, confidence: float}
            LLM-->>Engine: {severity: 85, type: "c2_communication", confidence: 0.92}

            Engine->>PG: UPDATE alerts SET<br/>severity_score = 85,<br/>alert_type = 'c2_communication',<br/>triage_confidence = 0.92,<br/>priority = 'P2',<br/>status = 'triaged'<br/>WHERE alert_id = 'alert_001'

            Engine->>PG: INSERT INTO audit_logs<br/>(actor, action, target, details, timestamp)<br/>VALUES ('agent', 'triage', 'alert_001', '{severity: 85}', NOW())

            Engine-->>API: TriageResult(severity=85, type="c2_communication", priority="P2")
        end

        API->>Redis: PUBLISH alert_events {type: "new_alert", alert_id: "alert_001", severity: 85}
        Note over Redis: WebSocket subscribers notified

        alt Severity >= 70 (High/Critical)
            API->>Slack: POST /api/chat.postMessage<br/>Channel: #soc-alerts<br/>Blocks: [Alert card with severity, type, IOCs]
            Slack-->>API: 200 OK {ts: "1751640310.000100"}
        end

        API-->>Splunk: 200 OK {status: "accepted", alert_id: "alert_001", severity: 85}
    end
```

## 2. IOC Enrichment Flow

```mermaid
sequenceDiagram
    participant Engine as Agent Engine
    participant MCP as MCP Server<br/>(Port 8002)
    participant Redis as Redis<br/>(Port 6379)
    participant VT as VirusTotal<br/>(api.virustotal.com)
    participant Abuse as AbuseIPDB<br/>(api.abuseipdb.com)
    participant MISP as MISP Server<br/>(misp.internal)
    participant Shodan as Shodan<br/>(api.shodan.io)
    participant PG as PostgreSQL<br/>(Port 5432)

    Note over Engine,PG: IOC Enrichment Flow - IP Address 203.0.113.42

    Engine->>MCP: JSON-RPC tools/call<br/>name: "enrich_ioc"<br/>args: {ioc_type: "ipv4", ioc_value: "203.0.113.42"}

    MCP->>MCP: Validate parameters against schema<br/>Check ioc_type enum, validate IP format

    MCP->>Redis: GET ioc:ipv4:203.0.113.42
    Redis-->>MCP: nil (cache miss)

    par Parallel Enrichment Queries
        MCP->>VT: GET /api/v3/ip_addresses/203.0.113.42<br/>x-apikey: {VT_API_KEY}<br/>Accept: application/json
        Note over MCP,VT: Rate limit: 4 req/min (free tier)
    and
        MCP->>Abuse: GET /api/v2/check?ipAddress=203.0.113.42&maxAgeInDays=90<br/>Key: {ABUSEIPDB_KEY}<br/>Accept: application/json
        Note over MCP,Abuse: Rate limit: 1000 req/day
    and
        MCP->>MISP: POST /attributes/restSearch<br/>Authorization: {MISP_KEY}<br/>{value: "203.0.113.42", type: "ip-src||ip-dst", limit: 10}
        Note over MCP,MISP: Self-hosted, no external rate limit
    and
        MCP->>Shodan: GET /shodan/host/203.0.113.42<br/>key={SHODAN_API_KEY}
        Note over MCP,Shodan: Rate limit: 1 req/sec
    end

    VT-->>MCP: 200 OK {data: {attributes: {<br/>last_analysis_stats: {malicious: 15, suspicious: 3, harmless: 70, undetected: 6},<br/>tags: ["malware", "c2"],<br/>whois: "Suspicious Hosting LLC"}}}

    Abuse-->>MCP: 200 OK {data: {<br/>abuseConfidenceScore: 95,<br/>totalReports: 342,<br/>lastReportedAt: "2026-07-04T08:00:00Z",<br/>usageType: "Data Center/Web Hosting"}}

    MISP-->>MCP: 200 OK {response: {Attribute: [<br/>{event_id: "evt-001", category: "Network activity", type: "ip-dst", Tag: [{name: "tlp:amber"}, {name: "Cobalt Strike"}]},<br/>{event_id: "evt-002", category: "Network activity"}]}}

    Shodan-->>MCP: 200 OK {<br/>ports: [80, 443, 8443],<br/>os: "Linux",<br/>org: "Suspicious Hosting LLC",<br/>country_code: "RU",<br/>vulns: ["CVE-2024-1234"]}

    MCP->>MCP: Calculate composite risk score<br/>VT: (15/94)*100*0.35 = 5.6<br/>Abuse: 95*0.25 = 23.8<br/>MISP: min(3*5, 25)*0.25 = 3.75 (normalized)<br/>Shodan: min(1*3, 15)*0.15 = 0.45<br/>Total normalized: 82

    MCP->>Redis: SETEX ioc:ipv4:203.0.113.42 3600<br/>{composite_risk_score: 82, sources: {...}, enriched_at: "..."}
    Redis-->>MCP: OK

    MCP->>PG: INSERT INTO ioc_enrichments<br/>(ioc_type, ioc_value, risk_score, vt_data, abuse_data, misp_data, shodan_data)<br/>VALUES ('ipv4', '203.0.113.42', 82, ...)
    PG-->>MCP: {enrichment_id: "enr_001"}

    MCP->>PG: INSERT INTO ioc_sightings<br/>(ioc_type, ioc_value, first_seen, last_seen, sighting_count)<br/>VALUES ('ipv4', '203.0.113.42', NOW(), NOW(), 1)<br/>ON CONFLICT (ioc_type, ioc_value) DO UPDATE<br/>SET last_seen = NOW(), sighting_count = sighting_count + 1

    MCP-->>Engine: JSON-RPC Response<br/>{content: [{type: "text", text: "{risk_score: 82, ...}"}]}
```

## 3. Incident Escalation Flow

```mermaid
sequenceDiagram
    participant Engine as Agent Engine
    participant PG as PostgreSQL<br/>(Port 5432)
    participant A2A as A2A Handler<br/>(Port 8003)
    participant IR as Incident Response Agent
    participant EDR as CrowdStrike Falcon<br/>(api.crowdstrike.com)
    participant SNOW as ServiceNow<br/>(instance.service-now.com)
    participant PD as PagerDuty<br/>(events.pagerduty.com)
    participant Slack as Slack API
    participant Teams as Microsoft Teams
    participant S3 as S3 Bucket

    Note over Engine,S3: Incident Escalation Flow - Critical Alert with Active Compromise

    Engine->>Engine: Composite risk score = 94 (Critical)<br/>MITRE: T1059.001 + T1071.001 + T1021.002<br/>Kill chain: Execution -> C2 -> Lateral Movement<br/>Decision: CONTAIN

    Engine->>PG: INSERT INTO investigations<br/>(investigation_id, alert_ids, severity, composite_score, status)<br/>VALUES ('inv-001', ARRAY['alert_001', 'alert_002'], 'critical', 94, 'active')
    PG-->>Engine: {investigation_id: "inv-001"}

    par Containment + Ticketing + Notification (Parallel)
        Engine->>A2A: POST /a2a/v1 (mTLS)<br/>tasks/send {action: "contain_threat",<br/>hosts: ["WORKSTATION-42"],<br/>users: ["jdoe@corp.local"],<br/>iocs: ["203.0.113.42"]}
        A2A->>IR: Forward containment request<br/>(mTLS, JSON-RPC 2.0)

        IR->>EDR: POST /devices/entities/devices-actions/v2<br/>Authorization: Bearer {oauth2_token}<br/>{action_name: "contain", ids: ["device_abc123"]}
        EDR-->>IR: 202 Accepted {resources: [{id: "device_abc123", status: "containment_pending"}]}

        IR->>EDR: GET /devices/entities/devices/v2?ids=device_abc123
        EDR-->>IR: 200 OK {resources: [{status: "contained"}]}

        IR-->>A2A: Task completed {containment_actions: [{type: "endpoint_isolation", status: "completed"}]}
        A2A-->>Engine: Containment result
    and
        Engine->>SNOW: POST /api/now/table/incident<br/>Authorization: Bearer {oauth2_token}<br/>{short_description: "Critical: Active C2 beacon + lateral movement",<br/>urgency: 1, impact: 1, priority: 1,<br/>category: "Security",<br/>assignment_group: "SOC-Tier3",<br/>description: "Investigation inv-001: Cobalt Strike beacon..."}
        SNOW-->>Engine: 201 Created {result: {number: "INC0012345", sys_id: "abc123"}}
    and
        Engine->>PD: POST /v2/enqueue<br/>Content-Type: application/json<br/>{routing_key: "soc-critical-key",<br/>event_action: "trigger",<br/>payload: {<br/>  summary: "CRITICAL: Active C2 beacon on WORKSTATION-42",<br/>  severity: "critical",<br/>  source: "soc-analyst-agent",<br/>  component: "WORKSTATION-42",<br/>  custom_details: {investigation_id: "inv-001", mitre: "T1059.001, T1071.001"}}}
        PD-->>Engine: 202 Accepted {dedup_key: "pd-event-001"}
    and
        Engine->>Slack: POST /api/chat.postMessage<br/>Authorization: Bearer {bot_token}<br/>{channel: "#soc-critical",<br/>blocks: [{type: "header", text: "CRITICAL: Active Compromise Detected"},<br/>{type: "section", fields: [<br/>  {type: "mrkdwn", text: "*Host:* WORKSTATION-42"},<br/>  {type: "mrkdwn", text: "*User:* jdoe"},<br/>  {type: "mrkdwn", text: "*MITRE:* T1059.001, T1071.001, T1021.002"},<br/>  {type: "mrkdwn", text: "*Score:* 94/100"}]},<br/>{type: "actions", elements: [{type: "button", text: "View Investigation", url: "https://soc.example.com/investigations/inv-001"}]}]}
        Slack-->>Engine: 200 OK
    and
        Engine->>Teams: POST /v1.0/teams/{teamId}/channels/{channelId}/messages<br/>Authorization: Bearer {graph_token}<br/>{body: {contentType: "html",<br/>content: "<h2>CRITICAL: Active Compromise</h2><p>Investigation: inv-001</p>"}}
        Teams-->>Engine: 201 Created
    end

    Engine->>Engine: Generate investigation playbook<br/>Template: cobalt_strike_c2_playbook<br/>Customize with IOCs, hosts, users

    Engine->>S3: PUT /soc-agent-artifacts/reports/inv-001.pdf<br/>Content-Type: application/pdf<br/>x-amz-server-side-encryption: AES256
    S3-->>Engine: 200 OK {ETag: "abc123"}

    Engine->>PG: UPDATE investigations SET<br/>status = 'contained',<br/>ticket_id = 'INC0012345',<br/>pagerduty_key = 'pd-event-001',<br/>report_url = 's3://soc-agent-artifacts/reports/inv-001.pdf',<br/>containment_completed_at = NOW()<br/>WHERE investigation_id = 'inv-001'

    Engine->>PG: INSERT INTO audit_logs<br/>(actor, action, target, details)<br/>VALUES ('agent', 'escalate_contain', 'inv-001',<br/>'{ticket: INC0012345, contained_hosts: ["WORKSTATION-42"]}')
```

## 4. User Chat Interaction Flow

```mermaid
sequenceDiagram
    participant Browser as SOC Analyst Browser
    participant WS as WebSocket<br/>(wss://soc.example.com/ws)
    participant API as FastAPI API<br/>(Port 8000)
    participant Engine as Agent Engine<br/>(Port 50051)
    participant RAG as RAG Pipeline<br/>(Port 8001)
    participant OS as OpenSearch<br/>(Port 9200)
    participant MCP as MCP Server<br/>(Port 8002)
    participant Splunk as Splunk SIEM
    participant LLM as OpenAI GPT-4o
    participant PG as PostgreSQL

    Note over Browser,PG: User Chat Interaction - Analyst Asks About Alert

    Browser->>WS: WebSocket Connect<br/>wss://soc.example.com/ws/chat<br/>Authorization: Bearer {jwt_token}
    WS->>API: Validate JWT, extract user claims
    API-->>WS: Connection established
    WS-->>Browser: Connected {session_id: "sess_001"}

    Browser->>WS: {type: "message",<br/>text: "What MITRE techniques are associated with alert alert_001?<br/>Can you check if the source IP has been seen before?"}
    WS->>API: Route to chat handler

    API->>Engine: gRPC ChatQuery(session_id="sess_001",<br/>query="What MITRE techniques...",<br/>alert_context="alert_001")

    Engine->>PG: SELECT * FROM alerts WHERE alert_id = 'alert_001'
    PG-->>Engine: {alert_payload with triage data}

    Engine->>PG: SELECT * FROM ioc_enrichments<br/>WHERE ioc_value = '203.0.113.42'<br/>ORDER BY enriched_at DESC LIMIT 1
    PG-->>Engine: {enrichment data}

    Engine->>RAG: POST /retrieve<br/>{query: "MITRE techniques PowerShell encoded command C2 beacon",<br/>top_k: 5, filters: {source: "mitre_attack"}}

    RAG->>OS: POST /knowledge-embeddings/_search<br/>{query: {hybrid: {queries: [<br/>  {match: {content: "PowerShell encoded command"}},<br/>  {knn: {embedding: [0.12, -0.34, ...], k: 20}}],<br/>  weights: [0.3, 0.7]}}, size: 20}
    OS-->>RAG: {hits: [{_source: {content: "T1059.001 PowerShell...", mitre_technique_id: "T1059.001"}, _score: 0.89}, ...]}

    RAG->>RAG: Cross-encoder reranking<br/>ms-marco-MiniLM-L-6-v2<br/>Select top 5

    RAG-->>Engine: {context: [<br/>{source: "MITRE ATT&CK T1059.001", content: "PowerShell..."},<br/>{source: "MITRE ATT&CK T1071.001", content: "Web Protocols..."},<br/>{source: "NIST SP 800-61r3", content: "Analysis procedures..."}]}

    Engine->>Engine: Decide tool calls needed:<br/>1. query_siem - check historical sightings<br/>2. Answer with RAG context

    Engine->>MCP: JSON-RPC tools/call<br/>name: "query_siem"<br/>args: {platform: "splunk",<br/>query: "index=* src_ip=203.0.113.42 | stats count by index, sourcetype, action | head 20",<br/>time_range: {start: "2026-06-04T00:00:00Z", end: "2026-07-04T23:59:59Z"}}

    MCP->>Splunk: POST /services/search/jobs<br/>Authorization: Bearer {splunk_token}<br/>{search: "search index=* src_ip=203.0.113.42 ..."}
    Splunk-->>MCP: 201 {sid: "job_12345"}
    MCP->>Splunk: GET /services/search/jobs/job_12345/results?output_mode=json
    Splunk-->>MCP: 200 {results: [{index: "main", sourcetype: "syslog", count: 47}, ...]}
    MCP-->>Engine: {siem_results: [{index: "main", count: 47}, {index: "proxy", count: 12}]}

    Engine->>LLM: POST /v1/chat/completions<br/>{model: "gpt-4o", temperature: 0.1,<br/>messages: [<br/>{role: "system", content: "You are a SOC analyst assistant...<br/>CONTEXT: [RAG retrieved chunks]"},<br/>{role: "user", content: "What MITRE techniques...<br/>Alert data: {alert payload}<br/>Enrichment: {enrichment data}<br/>SIEM History: {siem results}"}],<br/>response_format: {type: "json_schema", ...}}

    LLM-->>Engine: {choices: [{message: {content: "{<br/>mitre_techniques: [<br/>  {id: 'T1059.001', name: 'PowerShell', confidence: 0.95, evidence: '...'},<br/>  {id: 'T1071.001', name: 'Web Protocols', confidence: 0.88, evidence: '...'}],<br/>historical_activity: {total_events: 59, first_seen: '2026-06-28', ...},<br/>assessment: 'The source IP has been active for 7 days with 59 events...',<br/>recommendations: ['Investigate all 59 historical events', '...']}"}}]}

    Engine->>PG: INSERT INTO chat_messages<br/>(session_id, role, content, tool_calls, timestamp)<br/>VALUES ('sess_001', 'assistant', '{response}', '{tools used}', NOW())

    Engine-->>API: ChatResponse(message="{formatted response}")

    API->>WS: {type: "message",<br/>role: "assistant",<br/>content: "Based on my analysis of alert_001...<br/><br/>**MITRE ATT&CK Techniques:**<br/>1. T1059.001 (PowerShell) - Confidence: 95%...<br/>2. T1071.001 (Web Protocols) - Confidence: 88%...<br/><br/>**Historical Activity:**<br/>IP 203.0.113.42 has been seen 59 times...",<br/>sources: ["MITRE ATT&CK", "Splunk SIEM", "VirusTotal"],<br/>tool_calls: ["query_siem", "enrich_ioc"]}
    WS-->>Browser: Render response with<br/>source citations and<br/>interactive MITRE links
```

## Sequence Diagram Summary

| Flow | Components Involved | Avg Duration (p95) | Key Protocol |
|------|--------------------|--------------------|--------------|
| Alert Triage | Splunk -> API -> Redis -> Engine -> LLM -> PG -> Slack | 3.5s | HTTPS, gRPC, JSON-RPC |
| IOC Enrichment | Engine -> MCP -> VT/Abuse/MISP/Shodan -> Redis -> PG | 8.2s | HTTPS, JSON-RPC |
| Incident Escalation | Engine -> A2A/IR -> EDR + SNOW + PD + Slack + Teams | 12.5s | mTLS, OAuth2, REST |
| User Chat | Browser -> WS -> API -> Engine -> RAG/MCP -> LLM | 6.8s | WebSocket, gRPC, HTTPS |
