# ADR-003: Authentication Strategy

## Status

Accepted

## Date

2024-12-01

## Context

The SOC Analyst Agent exposes APIs that access sensitive security data (alerts, IOCs, incident reports). Authentication must be robust, support multiple client types (dashboard, CLI, other agents), and integrate with enterprise identity providers.

## Decision

Three-layer authentication:

1. **JWT (RS256)** for dashboard users — issued after OAuth2 PKCE flow with enterprise IdP (Azure AD, Okta)
2. **API Keys** for programmatic access — SHA-256 hashed, stored in PostgreSQL, scoped by permission
3. **mTLS** for agent-to-agent communication — mutual TLS with certificate-based identity

## Consequences

### Positive
- Dashboard users authenticate via existing enterprise SSO (no new credentials)
- API keys enable automation and CI/CD integration
- mTLS provides strongest authentication for inter-agent trust
- JWT RS256 allows token verification without calling the auth server

### Negative
- Three auth mechanisms increase implementation complexity
- Certificate management for mTLS requires PKI infrastructure
- API key rotation must be managed operationally

## RBAC Roles

| Role | Permissions |
|------|------------|
| `soc_analyst` | Triage alerts, enrich IOCs, query SIEM, generate playbooks |
| `soc_lead` | All analyst permissions + create incidents, modify verdicts |
| `soc_manager` | All lead permissions + view metrics, manage API keys |
| `admin` | Full access including configuration and user management |
| `service_account` | Scoped to specific API endpoints for automation |
