# -----------------------------------------------------------------------------
# EKS
# -----------------------------------------------------------------------------
output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "Endpoint URL for the EKS cluster API server"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_certificate_authority_data" {
  description = "Base64-encoded CA certificate for the EKS cluster"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "eks_cluster_oidc_provider_arn" {
  description = "ARN of the OIDC provider for IRSA"
  value       = module.eks.oidc_provider_arn
}

output "eks_cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "eks_node_security_group_id" {
  description = "Security group ID attached to the EKS managed node groups"
  value       = module.eks.node_security_group_id
}

# -----------------------------------------------------------------------------
# RDS PostgreSQL
# -----------------------------------------------------------------------------
output "rds_endpoint" {
  description = "Connection endpoint for the RDS PostgreSQL instance"
  value       = module.rds.db_instance_endpoint
}

output "rds_address" {
  description = "Hostname of the RDS PostgreSQL instance"
  value       = module.rds.db_instance_address
}

output "rds_port" {
  description = "Port number for the RDS PostgreSQL instance"
  value       = module.rds.db_instance_port
}

output "rds_database_name" {
  description = "Name of the default database"
  value       = module.rds.db_instance_name
}

output "rds_secret_arn" {
  description = "ARN of the Secrets Manager secret holding RDS credentials"
  value       = aws_secretsmanager_secret.rds_password.arn
}

# -----------------------------------------------------------------------------
# ElastiCache Redis
# -----------------------------------------------------------------------------
output "redis_primary_endpoint" {
  description = "Primary endpoint for the Redis replication group"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "redis_reader_endpoint" {
  description = "Reader endpoint for the Redis replication group"
  value       = aws_elasticache_replication_group.redis.reader_endpoint_address
}

output "redis_port" {
  description = "Port number for the Redis cluster"
  value       = aws_elasticache_replication_group.redis.port
}

output "redis_secret_arn" {
  description = "ARN of the Secrets Manager secret holding Redis auth token"
  value       = aws_secretsmanager_secret.redis_auth.arn
}

# -----------------------------------------------------------------------------
# OpenSearch
# -----------------------------------------------------------------------------
output "opensearch_endpoint" {
  description = "Endpoint URL for the OpenSearch domain"
  value       = aws_opensearch_domain.this.endpoint
}

output "opensearch_dashboard_endpoint" {
  description = "Kibana/Dashboards endpoint for the OpenSearch domain"
  value       = aws_opensearch_domain.this.dashboard_endpoint
}

output "opensearch_domain_arn" {
  description = "ARN of the OpenSearch domain"
  value       = aws_opensearch_domain.this.arn
}

output "opensearch_secret_arn" {
  description = "ARN of the Secrets Manager secret holding OpenSearch credentials"
  value       = aws_secretsmanager_secret.opensearch.arn
}

# -----------------------------------------------------------------------------
# S3 Backups
# -----------------------------------------------------------------------------
output "backups_bucket_name" {
  description = "Name of the S3 bucket for backups"
  value       = aws_s3_bucket.backups.id
}

output "backups_bucket_arn" {
  description = "ARN of the S3 bucket for backups"
  value       = aws_s3_bucket.backups.arn
}

# -----------------------------------------------------------------------------
# KMS
# -----------------------------------------------------------------------------
output "kms_key_arn" {
  description = "ARN of the KMS encryption key"
  value       = aws_kms_key.main.arn
}

output "kms_key_id" {
  description = "ID of the KMS encryption key"
  value       = aws_kms_key.main.key_id
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_private_subnets" {
  description = "List of private subnet IDs"
  value       = module.vpc.private_subnets
}

output "vpc_public_subnets" {
  description = "List of public subnet IDs"
  value       = module.vpc.public_subnets
}

output "vpc_isolated_subnets" {
  description = "List of isolated (intra) subnet IDs"
  value       = module.vpc.intra_subnets
}

# -----------------------------------------------------------------------------
# IAM
# -----------------------------------------------------------------------------
output "soc_analyst_irsa_role_arn" {
  description = "ARN of the IAM role for SOC Analyst service account (IRSA)"
  value       = module.soc_analyst_irsa.iam_role_arn
}
