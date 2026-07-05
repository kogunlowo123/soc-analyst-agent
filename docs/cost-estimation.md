# SOC Analyst Agent — Cost Estimation

## Monthly Cost by Cloud Provider

### AWS Deployment

| Service | Specification | Monthly Cost |
|---------|--------------|-------------|
| EKS Cluster | 1 cluster, 3 m6i.xlarge nodes | $220 |
| RDS PostgreSQL | db.r6g.large, Multi-AZ, 100GB gp3 | $380 |
| ElastiCache Redis | cache.r6g.large, 2 nodes | $290 |
| OpenSearch | 3x r6g.large.search, 500GB gp3 | $680 |
| S3 | 100GB storage, 1M requests | $5 |
| CloudWatch | Logs (50GB), Metrics, Alarms | $80 |
| ALB | 1 ALB, 100 LCU-hours | $30 |
| ECR | 10GB images | $1 |
| Secrets Manager | 20 secrets | $8 |
| KMS | 1 key, 10K requests | $1 |
| NAT Gateway | 2 AZs, 100GB data | $90 |
| **AWS Total** | | **$1,785/mo** |

### LLM API Costs

| Provider | Model | Usage Estimate | Monthly Cost |
|----------|-------|---------------|-------------|
| OpenAI | GPT-4o | 5M input + 1M output tokens | $75 |
| OpenAI | text-embedding-3-large | 2M tokens | $26 |
| Anthropic | Claude 3.5 Sonnet | 5M input + 1M output tokens | $45 |
| Amazon Bedrock | Claude 3.5 Sonnet | 5M input + 1M output tokens | $45 |
| **LLM Total** | | | **$45-101/mo** |

### Threat Intelligence API Costs

| Service | Tier | Monthly Cost |
|---------|------|-------------|
| VirusTotal | Premium (30K lookups/day) | $800 |
| AbuseIPDB | Pro (5K checks/day) | $99 |
| MISP | Self-hosted (included in infra) | $0 |
| **Threat Intel Total** | | **$899/mo** |

### Total Monthly Cost

| Component | Cost |
|-----------|------|
| Cloud Infrastructure (AWS) | $1,785 |
| LLM APIs | $75 |
| Threat Intelligence | $899 |
| **Grand Total** | **$2,759/mo** |

## Cost Optimization Strategies

| Strategy | Savings | Implementation |
|----------|---------|---------------|
| Reserved Instances (1-year) | 30-40% on compute | Commit to EKS nodes and RDS |
| Spot Instances for workers | 60-80% on batch processing | Use spot for Celery workers |
| Prompt caching | 20-30% on LLM costs | Cache common triage prompts |
| IOC enrichment caching | 40-50% on threat intel | Cache IOC results in Redis (TTL: 24h) |
| OpenSearch reserved | 30% on search | Reserved instances for OpenSearch |
| Right-sizing after 30 days | 10-20% overall | Monitor actual usage and downsize |

### Optimized Monthly Cost (with reservations and caching)

| Component | Original | Optimized |
|-----------|----------|-----------|
| Cloud Infrastructure | $1,785 | $1,200 |
| LLM APIs | $75 | $55 |
| Threat Intelligence | $899 | $600 |
| **Total** | **$2,759** | **$1,855/mo** |

## Cost per Alert

| Metric | Value |
|--------|-------|
| Alerts processed per month | ~150,000 |
| Cost per alert (original) | $0.018 |
| Cost per alert (optimized) | $0.012 |
| Cost per incident report | $0.15 |

## Scaling Cost Impact

| Scale | Alerts/month | Monthly Cost | Cost/Alert |
|-------|-------------|-------------|-----------|
| Small SOC | 50,000 | $2,200 | $0.044 |
| Medium SOC | 150,000 | $2,759 | $0.018 |
| Large SOC | 500,000 | $4,500 | $0.009 |
| Enterprise SOC | 1,000,000 | $7,200 | $0.007 |
