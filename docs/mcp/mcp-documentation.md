# SOC Analyst Agent — MCP Server Documentation

## Overview

The Model Context Protocol (MCP) server exposes the SOC Analyst Agent's domain-specific tools as a standardized tool registry. This enables LLMs to discover and invoke security operations tools through a consistent interface.

## MCP Server Configuration

| Setting | Value |
|---------|-------|
| Server Name | `soc-analyst-agent-mcp` |
| Port | 8001 |
| Protocol | MCP over stdio / HTTP SSE |
| Authentication | API key (X-API-Key header) |
| Transport | stdio (local), HTTP SSE (remote) |

## Tool Registry

The MCP server registers the following domain-specific tools:

### triage_alert

Triage a security alert and determine if it is a true positive, false positive, or requires investigation.

```json
{
  "name": "triage_alert",
  "description": "Triage a security alert and determine if it is a true positive",
  "inputSchema": {
    "type": "object",
    "properties": {
      "alert_id": { "type": "string", "description": "Unique alert identifier" },
      "alert_data": {
        "type": "object",
        "description": "Alert metadata including source, severity, rule name, and raw log data",
        "properties": {
          "source": { "type": "string", "enum": ["splunk", "elastic", "sentinel", "crowdstrike"] },
          "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
          "rule_name": { "type": "string" },
          "raw_log": { "type": "string" }
        }
      }
    },
    "required": ["alert_id", "alert_data"]
  }
}
```

### enrich_ioc

Enrich an indicator of compromise with multi-source threat intelligence.

```json
{
  "name": "enrich_ioc",
  "description": "Enrich an indicator of compromise with threat intelligence",
  "inputSchema": {
    "type": "object",
    "properties": {
      "indicator": { "type": "string", "description": "The IOC value (IP, domain, hash, URL)" },
      "indicator_type": { "type": "string", "enum": ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"] }
    },
    "required": ["indicator", "indicator_type"]
  }
}
```

### correlate_events

Correlate security events across multiple SIEM data sources.

```json
{
  "name": "correlate_events",
  "description": "Correlate security events across multiple log sources",
  "inputSchema": {
    "type": "object",
    "properties": {
      "query": { "type": "string", "description": "Natural language or structured query" },
      "time_range": { "type": "string", "description": "Time range (e.g., 1h, 4h, 24h, 7d)" },
      "data_sources": { "type": "array", "items": { "type": "string" }, "description": "SIEM sources to query" }
    },
    "required": ["query", "time_range"]
  }
}
```

### query_siem

Execute a SIEM query using natural language or native query syntax (SPL, KQL, Lucene).

```json
{
  "name": "query_siem",
  "description": "Execute a SIEM query (supports natural language and SPL/KQL/Lucene)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "query": { "type": "string" },
      "index": { "type": "string" },
      "time_range": { "type": "string" }
    },
    "required": ["query", "time_range"]
  }
}
```

### generate_investigation

Generate a step-by-step investigation playbook for a specific alert type.

```json
{
  "name": "generate_investigation",
  "description": "Generate step-by-step investigation playbook for an alert type",
  "inputSchema": {
    "type": "object",
    "properties": {
      "alert_type": { "type": "string", "description": "Type of alert (e.g., suspicious_powershell, brute_force)" },
      "context": { "type": "object", "description": "Additional context about the alert" }
    },
    "required": ["alert_type"]
  }
}
```

### create_incident_report

Create a structured incident summary report from investigation findings.

```json
{
  "name": "create_incident_report",
  "description": "Create a structured incident summary report",
  "inputSchema": {
    "type": "object",
    "properties": {
      "alert_ids": { "type": "array", "items": { "type": "string" } },
      "findings": { "type": "object" },
      "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] }
    },
    "required": ["alert_ids", "findings", "severity"]
  }
}
```

## Resource Registry

The MCP server also exposes these resources for context retrieval:

| Resource URI | Description |
|-------------|-------------|
| `soc://alerts/recent` | Last 100 security alerts with triage status |
| `soc://incidents/open` | Currently open incidents |
| `soc://iocs/watchlist` | Active IOC watchlist |
| `soc://playbooks/index` | Available investigation playbooks |
| `soc://metrics/dashboard` | Current SOC operational metrics |

## Integration

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "soc-analyst": {
      "command": "uvicorn",
      "args": ["src.mcp.server:app", "--port", "8001"],
      "env": {
        "SIEM_URL": "https://splunk.example.com:8089",
        "VT_API_KEY": "your-virustotal-key"
      }
    }
  }
}
```

### Programmatic Usage

```python
from src.mcp.server import MCPServer

server = MCPServer()
tools = server.list_tools()
result = await server.call_tool("enrich_ioc", {
    "indicator": "203.0.113.50",
    "indicator_type": "ipv4"
})
```
