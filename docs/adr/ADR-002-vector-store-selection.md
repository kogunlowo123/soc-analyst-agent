# ADR-002: Vector Store Selection

## Status

Accepted

## Date

2024-12-01

## Context

The RAG pipeline requires a vector store for storing and retrieving security knowledge base embeddings. The store must support hybrid search (vector + keyword), metadata filtering, and handle approximately 260,000 documents.

## Options Considered

| Option | Hybrid Search | Managed Service | Cost (260K docs) | Latency (P95) |
|--------|:---:|:---:|---|---|
| OpenSearch | Yes | AWS/Self-hosted | $150-400/mo | 35ms |
| PostgreSQL + pgvector | Limited | All clouds | $50-150/mo | 80ms |
| Pinecone | No native BM25 | Managed only | $70-200/mo | 20ms |
| Weaviate | Yes | Self-hosted/Cloud | $100-300/mo | 30ms |
| Qdrant | No native BM25 | Self-hosted/Cloud | $80-200/mo | 15ms |

## Decision

**OpenSearch** as the primary vector store.

## Consequences

### Positive
- Native hybrid search (kNN + BM25) in a single query
- Metadata filtering for document type, source, and date range
- Self-hosted option for data sovereignty requirements
- AWS OpenSearch Serverless available for managed deployments
- Strong ecosystem for log analytics (dual-purpose with SIEM data)

### Negative
- Higher memory footprint than specialized vector databases
- HNSW index requires more storage than flat indexes
- Cluster management overhead if self-hosted

## Rationale

Security operations already use OpenSearch/Elasticsearch for log analytics. Using OpenSearch for the vector store avoids introducing a separate data system and leverages existing operational expertise. The hybrid search capability is critical for security content where exact keyword matches (CVE IDs, technique IDs) are as important as semantic similarity.
