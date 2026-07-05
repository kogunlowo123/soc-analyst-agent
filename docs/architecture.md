# SOC Analyst Agent Architecture

AI-powered SOC Tier 1/2 analyst that triages security alerts, enriches indicators of compromise, correlates events across SIEM data, generates investigation playbooks, and produces incident summary reports for escalation.

## Domain Tools

- **triage_alert**: Triage a security alert and determine if it is a true positive
- **enrich_ioc**: Enrich an indicator of compromise with threat intelligence
- **correlate_events**: Correlate security events across multiple log sources
- **query_siem**: Execute a SIEM query (KQL, SPL, or Lucene)
- **generate_investigation**: Generate step-by-step investigation playbook for an alert type
- **create_incident_report**: Create a structured incident summary report