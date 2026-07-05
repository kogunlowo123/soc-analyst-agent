# ADR-001: LLM Provider Selection

## Status

Accepted

## Date

2024-12-01

## Context

The SOC Analyst Agent requires an LLM for alert triage, investigation playbook generation, and report writing. The LLM must support tool calling, structured output, and operate within enterprise security requirements.

## Options Considered

| Option | Pros | Cons |
|--------|------|------|
| OpenAI GPT-4o | Best tool calling, structured output, wide ecosystem | Data leaves organization, cost at scale |
| Anthropic Claude 3.5 Sonnet | Strong reasoning, large context (200K), good safety | Fewer tool calling features than GPT-4o |
| Azure OpenAI GPT-4o | Same capability as OpenAI, data stays in Azure tenant | Azure-only, slightly higher latency |
| Amazon Bedrock (Claude) | AWS-native, data stays in AWS, multiple model choice | Additional Bedrock overhead |
| Self-hosted (Llama 3.1 70B) | Full data control, no API costs | High infrastructure cost, lower quality |

## Decision

Support **multi-provider** architecture with Azure OpenAI GPT-4o as the default for enterprise deployments, with Anthropic Claude 3.5 Sonnet and Amazon Bedrock as alternatives. The `LLM_MODEL` environment variable controls provider selection at deployment time.

## Consequences

### Positive
- Enterprise customers can choose based on their cloud provider
- No vendor lock-in
- Data residency requirements can be met with any provider

### Negative
- Must maintain compatibility with multiple provider APIs
- Testing matrix increases (test with each provider)
- Feature availability varies (GPT-4o structured output vs Claude XML tags)

## Rationale

Security operations require data to remain within the organization's cloud environment. Multi-provider support allows each customer to select the provider that meets their compliance requirements while maintaining the same agent capabilities.
