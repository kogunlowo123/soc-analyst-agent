# A2A Communication Architecture

## Overview

The SOC Analyst Agent communicates with peer security agents using the Agent-to-Agent (A2A) protocol, enabling collaborative investigation workflows across specialized agents. Each agent publishes an Agent Card describing its capabilities, and agents exchange tasks via JSON-RPC over HTTPS with mutual TLS authentication.

## A2A Agent Network Diagram

```mermaid
graph TB
    subgraph SOC_Agent["SOC Analyst Agent"]
        soc_a2a["A2A Handler<br/>Port: 8003<br/>Endpoint: /a2a/v1<br/>Protocol: JSON-RPC 2.0 over HTTPS"]
        soc_card["Agent Card<br/>Name: soc-analyst<br/>Skills: alert_triage,<br/>ioc_enrichment,<br/>event_correlation,<br/>mitre_mapping,<br/>investigation_report"]
        soc_engine["Agent Engine<br/>Processes inbound tasks<br/>Dispatches outbound requests"]
    end

    subgraph Threat_Hunter["Threat Hunting Agent"]
        th_a2a["A2A Handler<br/>Port: 8003<br/>Endpoint: /a2a/v1"]
        th_card["Agent Card<br/>Name: threat-hunter<br/>Skills: threat_hunt,<br/>hypothesis_generation,<br/>ioc_sweep,<br/>lateral_movement_detection,<br/>persistence_detection"]
    end

    subgraph IR_Agent["Incident Response Agent"]
        ir_a2a["A2A Handler<br/>Port: 8003<br/>Endpoint: /a2a/v1"]
        ir_card["Agent Card<br/>Name: incident-responder<br/>Skills: contain_threat,<br/>eradicate_malware,<br/>recover_systems,<br/>forensic_collection,<br/>timeline_reconstruction"]
    end

    subgraph Vuln_Agent["Vulnerability Management Agent"]
        vuln_a2a["A2A Handler<br/>Port: 8003<br/>Endpoint: /a2a/v1"]
        vuln_card["Agent Card<br/>Name: vuln-manager<br/>Skills: vulnerability_scan,<br/>patch_assessment,<br/>risk_scoring,<br/>cve_analysis,<br/>asset_exposure"]
    end

    subgraph Discovery["Agent Discovery Service"]
        registry["Agent Registry<br/>PostgreSQL table<br/>agent_cards"]
        health["Health Monitor<br/>Periodic health checks<br/>every 30 seconds"]
    end

    soc_a2a <-->|"Request: hunt_for_iocs<br/>Response: hunt_results"| th_a2a
    soc_a2a <-->|"Request: contain_endpoint<br/>Response: containment_status"| ir_a2a
    soc_a2a <-->|"Request: assess_vulnerability<br/>Response: vuln_context"| vuln_a2a
    th_a2a <-->|"Request: investigate_alert<br/>Response: investigation_report"| soc_a2a
    ir_a2a <-->|"Request: enrich_iocs<br/>Response: enrichment_data"| soc_a2a

    soc_card --> registry
    th_card --> registry
    ir_card --> registry
    vuln_card --> registry

    health --> soc_a2a
    health --> th_a2a
    health --> ir_a2a
    health --> vuln_a2a

    style SOC_Agent fill:#e8f5e9,stroke:#388e3c
    style Threat_Hunter fill:#e3f2fd,stroke:#1565c0
    style IR_Agent fill:#fce4ec,stroke:#c62828
    style Vuln_Agent fill:#fff3e0,stroke:#f57c00
    style Discovery fill:#f3e5f5,stroke:#7b1fa2
```

## Agent Card Definitions

### SOC Analyst Agent Card

```json
{
  "name": "soc-analyst",
  "description": "AI-powered SOC analyst that triages security alerts, enriches IOCs with threat intelligence, correlates events, maps to MITRE ATT&CK, and generates investigation playbooks.",
  "url": "https://soc-agent.internal:8003/a2a/v1",
  "version": "1.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": true,
    "stateTransitionHistory": true
  },
  "authentication": {
    "schemes": ["mtls"],
    "mtls": {
      "ca_cert": "/certs/ca.pem",
      "client_cert_required": true
    }
  },
  "skills": [
    {
      "id": "alert_triage",
      "name": "Alert Triage",
      "description": "Classify and prioritize security alerts from SIEM platforms with severity scoring (Critical/High/Medium/Low/Info) and investigation depth determination.",
      "inputModes": ["application/json"],
      "outputModes": ["application/json"]
    },
    {
      "id": "ioc_enrichment",
      "name": "IOC Enrichment",
      "description": "Extract and enrich IOCs (IPs, domains, hashes, URLs) with threat intelligence from VirusTotal, AbuseIPDB, MISP, and Shodan. Returns composite risk scores.",
      "inputModes": ["application/json"],
      "outputModes": ["application/json"]
    },
    {
      "id": "event_correlation",
      "name": "Event Correlation",
      "description": "Correlate security alerts by shared IOCs, affected assets, temporal proximity, and kill chain progression. Returns incident clusters with confidence scores.",
      "inputModes": ["application/json"],
      "outputModes": ["application/json"]
    },
    {
      "id": "mitre_mapping",
      "name": "MITRE ATT&CK Mapping",
      "description": "Map observed attacker behaviors to MITRE ATT&CK tactics and techniques with confidence scoring.",
      "inputModes": ["application/json"],
      "outputModes": ["application/json"]
    },
    {
      "id": "investigation_report",
      "name": "Investigation Report",
      "description": "Generate structured incident investigation reports with executive summary, IOC tables, MITRE mapping, timeline, and recommended actions.",
      "inputModes": ["application/json"],
      "outputModes": ["application/json", "text/html", "application/pdf"]
    }
  ]
}
```

## Inter-Agent Communication Flows

### Flow 1: SOC Agent to Threat Hunting Agent

```mermaid
sequenceDiagram
    participant SOC as SOC Analyst Agent
    participant Registry as Agent Registry
    participant TH as Threat Hunting Agent

    Note over SOC: Alert triage reveals suspicious<br/>C2 beacon pattern on host

    SOC->>Registry: GET /agents?skill=threat_hunt
    Registry-->>SOC: {agent: "threat-hunter", url: "https://threat-hunter.internal:8003/a2a/v1"}

    SOC->>TH: POST /a2a/v1 (mTLS)
    Note right of SOC: JSON-RPC Request:<br/>method: "tasks/send"<br/>params: {<br/>  id: "task-uuid-001",<br/>  message: {<br/>    role: "user",<br/>    parts: [{<br/>      type: "text",<br/>      text: "Hunt for C2 indicators..."<br/>    }, {<br/>      type: "data",<br/>      data: {<br/>        iocs: ["203.0.113.42", "evil.example.com"],<br/>        host: "WORKSTATION-42",<br/>        timeframe: "72h",<br/>        hypothesis: "APT lateral movement via<br/>        Cobalt Strike beacon"<br/>      }<br/>    }]<br/>  }<br/>}

    TH-->>SOC: 200 OK {id: "task-uuid-001", status: {state: "submitted"}}

    Note over TH: Threat Hunting Agent executes:<br/>1. SIEM sweep for beacon patterns<br/>2. DNS query analysis for C2 domains<br/>3. Process tree analysis on host<br/>4. Lateral movement detection

    TH->>SOC: POST /a2a/v1/tasks/task-uuid-001/status (webhook)
    Note left of TH: status: {state: "working",<br/>message: "Executing IOC sweep across<br/>14-day log window"}

    TH->>SOC: POST /a2a/v1/tasks/task-uuid-001/status (webhook)
    Note left of TH: status: {<br/>  state: "completed",<br/>  message: {<br/>    role: "agent",<br/>    parts: [{<br/>      type: "data",<br/>      data: {<br/>        findings: [<br/>          {host: "WORKSTATION-42", beacon_interval: "60s", c2_domain: "evil.example.com"},<br/>          {host: "SERVER-DB-01", lateral_movement: true, technique: "T1021.002"}],<br/>        additional_iocs: ["10.0.10.55", "beacon.evil.com"],<br/>        confidence: 0.91,<br/>        recommendation: "Immediate containment of both hosts"<br/>      }<br/>    }]<br/>  }<br/>}

    Note over SOC: SOC Agent updates investigation<br/>with hunt findings, escalates severity,<br/>requests containment from IR Agent
```

### Flow 2: SOC Agent to Incident Response Agent

```mermaid
sequenceDiagram
    participant SOC as SOC Analyst Agent
    participant IR as Incident Response Agent
    participant EDR as CrowdStrike EDR
    participant AD as Active Directory

    Note over SOC: Investigation confirms active<br/>compromise, containment required

    SOC->>IR: POST /a2a/v1 (mTLS)
    Note right of SOC: method: "tasks/send"<br/>params: {<br/>  id: "task-uuid-002",<br/>  message: {<br/>    parts: [{<br/>      type: "data",<br/>      data: {<br/>        action: "contain_threat",<br/>        hosts: ["WORKSTATION-42", "SERVER-DB-01"],<br/>        user_accounts: ["jdoe@corp.local"],<br/>        iocs_to_block: ["203.0.113.42", "evil.example.com"],<br/>        severity: "critical",<br/>        investigation_id: "inv-2026-0704-001"<br/>      }<br/>    }]<br/>  }<br/>}

    IR-->>SOC: 200 OK {status: {state: "submitted"}}

    IR->>EDR: POST /devices/entities/devices-actions/v2 (isolate)
    EDR-->>IR: 200 OK {resources: [{device_id: "abc123", status: "isolated"}]}

    IR->>AD: LDAP Modify (disable account jdoe, port 636)
    AD-->>IR: Success

    IR->>SOC: POST /a2a/v1/tasks/task-uuid-002/status
    Note left of IR: status: {state: "completed",<br/>  data: {<br/>    containment_actions: [<br/>      {type: "endpoint_isolation", host: "WORKSTATION-42", status: "isolated"},<br/>      {type: "endpoint_isolation", host: "SERVER-DB-01", status: "isolated"},<br/>      {type: "account_disable", account: "jdoe@corp.local", status: "disabled"},<br/>      {type: "ioc_block", ioc: "203.0.113.42", status: "blocked_at_firewall"},<br/>      {type: "ioc_block", ioc: "evil.example.com", status: "blocked_at_dns"}],<br/>    timestamp: "2026-07-04T14:23:00Z"<br/>  }<br/>}
```

### Flow 3: SOC Agent to Vulnerability Management Agent

```mermaid
sequenceDiagram
    participant SOC as SOC Analyst Agent
    participant Vuln as Vuln Management Agent
    participant NVD as NIST NVD API

    Note over SOC: Alert references CVE-2026-12345<br/>Need vulnerability context for<br/>severity assessment

    SOC->>Vuln: POST /a2a/v1 (mTLS)
    Note right of SOC: method: "tasks/send"<br/>params: {<br/>  id: "task-uuid-003",<br/>  message: {parts: [{type: "data", data: {<br/>    action: "assess_vulnerability",<br/>    cve_ids: ["CVE-2026-12345"],<br/>    affected_hosts: ["SERVER-WEB-01"],<br/>    context: "Exploitation attempt detected in WAF logs"<br/>  }}]}<br/>}

    Vuln-->>SOC: 200 OK {status: {state: "submitted"}}

    Vuln->>NVD: GET /rest/json/cves/2.0?cveId=CVE-2026-12345
    NVD-->>Vuln: 200 OK {vulnerabilities: [{cve: {id: "CVE-2026-12345", ...}}]}

    Vuln->>SOC: POST /a2a/v1/tasks/task-uuid-003/status
    Note left of Vuln: status: {state: "completed",<br/>  data: {<br/>    cve_analysis: {<br/>      id: "CVE-2026-12345",<br/>      cvss_v3_score: 9.8,<br/>      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",<br/>      exploitation_status: "active_exploitation",<br/>      patch_available: true,<br/>      patch_id: "KB5041234",<br/>      affected_assets: [{<br/>        host: "SERVER-WEB-01",<br/>        vulnerable_version: "2.14.0",<br/>        patched_version: "2.14.3",<br/>        exposure: "internet_facing"<br/>      }],<br/>      risk_rating: "critical",<br/>      recommendation: "Emergency patch within 24 hours"<br/>    }<br/>  }<br/>}
```

## Task Lifecycle States

```mermaid
stateDiagram-v2
    [*] --> submitted: tasks/send
    submitted --> working: Agent accepts task
    working --> working: Progress update
    working --> input_required: Agent needs more info
    input_required --> working: Additional data provided
    working --> completed: Task finished successfully
    working --> failed: Task execution error
    working --> canceled: Requester cancels
    completed --> [*]
    failed --> [*]
    canceled --> [*]
```

| State | Description | Transitions From | Transitions To |
|-------|-------------|-----------------|----------------|
| `submitted` | Task received and queued | Initial state | `working` |
| `working` | Agent actively processing the task | `submitted`, `input_required` | `completed`, `failed`, `canceled`, `input_required` |
| `input_required` | Agent needs additional information from requester | `working` | `working` (after input provided) |
| `completed` | Task finished successfully with results | `working` | Terminal state |
| `failed` | Task failed with error details | `working` | Terminal state |
| `canceled` | Task canceled by requester | `working` | Terminal state |

## Security Configuration

| Parameter | Value |
|-----------|-------|
| Transport | HTTPS with mutual TLS (mTLS) |
| Certificate Authority | Internal PKI (AWS Private CA) |
| Certificate Rotation | 90-day automatic rotation |
| Authentication | X.509 client certificate + Agent ID validation |
| Authorization | Agent capability allowlist (which agents can invoke which skills) |
| Message Signing | HMAC-SHA256 on request body for integrity verification |
| Rate Limiting | 30 requests/minute per peer agent |
| Timeout | 120 seconds for task submission, 3600 seconds for task completion |
| Retry Policy | 3 retries with exponential backoff (base 5s, max 60s) |
| Circuit Breaker | Open after 5 consecutive failures, half-open after 120s |

## Agent Authorization Matrix

| Requesting Agent | Allowed Skills on SOC Agent | Denied Skills |
|-----------------|----------------------------|---------------|
| threat-hunter | `ioc_enrichment`, `event_correlation`, `mitre_mapping` | `alert_triage` (internal only) |
| incident-responder | `ioc_enrichment`, `investigation_report`, `event_correlation` | `alert_triage` (internal only) |
| vuln-manager | `ioc_enrichment`, `mitre_mapping` | `alert_triage`, `investigation_report` |
| External/Unknown | None (rejected at mTLS handshake) | All |
