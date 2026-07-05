terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# -----------------------------------------------------------------------------
# Provider configuration
# -----------------------------------------------------------------------------
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "soc-analyst-agent"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = var.owner
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

# -----------------------------------------------------------------------------
# Data sources
# -----------------------------------------------------------------------------
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

# -----------------------------------------------------------------------------
# Locals
# -----------------------------------------------------------------------------
locals {
  name_prefix = "soc-analyst-${var.environment}"
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)

  vpc_cidr         = var.vpc_cidr
  public_subnets   = [for i, az in local.azs : cidrsubnet(local.vpc_cidr, 4, i)]
  private_subnets  = [for i, az in local.azs : cidrsubnet(local.vpc_cidr, 4, i + 3)]
  isolated_subnets = [for i, az in local.azs : cidrsubnet(local.vpc_cidr, 4, i + 6)]
}

# -----------------------------------------------------------------------------
# KMS – master encryption key
# -----------------------------------------------------------------------------
resource "aws_kms_key" "main" {
  description             = "SOC Analyst Agent master encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEKSServiceRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })

  tags = {
    Name = "${local.name_prefix}-kms"
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.main.key_id
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"

  name = "${local.name_prefix}-vpc"
  cidr = local.vpc_cidr
  azs  = local.azs

  public_subnets  = local.public_subnets
  private_subnets = local.private_subnets
  intra_subnets   = local.isolated_subnets

  enable_nat_gateway   = true
  single_nat_gateway   = var.environment != "production"
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name_prefix}-default-nacl" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name_prefix}-default-rt" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name_prefix}-default-sg" }

  public_subnet_tags = {
    "kubernetes.io/role/elb"                    = 1
    "kubernetes.io/cluster/${local.name_prefix}" = "shared"
    Tier                                         = "public"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"            = 1
    "kubernetes.io/cluster/${local.name_prefix}" = "shared"
    Tier                                         = "private"
  }

  intra_subnet_tags = {
    Tier = "isolated"
  }

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

# -----------------------------------------------------------------------------
# Security Groups
# -----------------------------------------------------------------------------
resource "aws_security_group" "rds" {
  name_prefix = "${local.name_prefix}-rds-"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "PostgreSQL from private subnets"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-rds-sg"
  }
}

resource "aws_security_group" "redis" {
  name_prefix = "${local.name_prefix}-redis-"
  description = "Security group for ElastiCache Redis"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Redis from EKS nodes"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-redis-sg"
  }
}

resource "aws_security_group" "opensearch" {
  name_prefix = "${local.name_prefix}-opensearch-"
  description = "Security group for OpenSearch domain"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "HTTPS from EKS nodes"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-opensearch-sg"
  }
}

# -----------------------------------------------------------------------------
# EKS Cluster
# -----------------------------------------------------------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = local.name_prefix
  cluster_version = var.eks_cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  enable_cluster_creator_admin_permissions = true

  cluster_encryption_config = {
    provider_key_arn = aws_kms_key.main.arn
    resources        = ["secrets"]
  }

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.ebs_csi_irsa.iam_role_arn
    }
  }

  eks_managed_node_groups = {
    general = {
      name            = "${local.name_prefix}-general"
      instance_types  = var.eks_node_instance_types
      capacity_type   = "ON_DEMAND"
      min_size        = var.eks_node_min_size
      max_size        = var.eks_node_max_size
      desired_size    = var.eks_node_desired_size
      disk_size       = 50
      ami_type        = "AL2_x86_64"

      labels = {
        role = "general"
      }

      tags = {
        Name = "${local.name_prefix}-eks-node"
      }
    }

    spot = {
      name            = "${local.name_prefix}-spot"
      instance_types  = var.eks_spot_instance_types
      capacity_type   = "SPOT"
      min_size        = 0
      max_size        = var.eks_node_max_size
      desired_size    = 0
      disk_size       = 50
      ami_type        = "AL2_x86_64"

      labels = {
        role     = "spot"
        workload = "non-critical"
      }

      taints = [{
        key    = "spot"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]

      tags = {
        Name = "${local.name_prefix}-eks-spot"
      }
    }
  }

  tags = {
    Name = "${local.name_prefix}-eks"
  }
}

module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.37"

  role_name_prefix      = "${local.name_prefix}-ebs-csi-"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

# -----------------------------------------------------------------------------
# IAM – IRSA for the SOC Analyst workload
# -----------------------------------------------------------------------------
module "soc_analyst_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.37"

  role_name_prefix = "${local.name_prefix}-app-"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["soc-analyst:soc-analyst-agent"]
    }
  }

  role_policy_arns = {
    s3      = aws_iam_policy.soc_analyst_s3.arn
    kms     = aws_iam_policy.soc_analyst_kms.arn
    secrets = aws_iam_policy.soc_analyst_secrets.arn
  }
}

resource "aws_iam_policy" "soc_analyst_s3" {
  name_prefix = "${local.name_prefix}-s3-"
  description = "S3 access for SOC Analyst backups"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject",
        ]
        Resource = [
          aws_s3_bucket.backups.arn,
          "${aws_s3_bucket.backups.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_policy" "soc_analyst_kms" {
  name_prefix = "${local.name_prefix}-kms-"
  description = "KMS access for SOC Analyst encryption"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = [aws_kms_key.main.arn]
      },
    ]
  })
}

resource "aws_iam_policy" "soc_analyst_secrets" {
  name_prefix = "${local.name_prefix}-secrets-"
  description = "Secrets Manager access for SOC Analyst"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${local.name_prefix}/*",
        ]
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# RDS PostgreSQL 16
# -----------------------------------------------------------------------------
resource "random_password" "rds" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "rds_password" {
  name_prefix = "${local.name_prefix}-rds-password-"
  kms_key_id  = aws_kms_key.main.arn

  tags = {
    Name = "${local.name_prefix}-rds-password"
  }
}

resource "aws_secretsmanager_secret_version" "rds_password" {
  secret_id = aws_secretsmanager_secret.rds_password.id
  secret_string = jsonencode({
    username = var.rds_master_username
    password = random_password.rds.result
    host     = module.rds.db_instance_address
    port     = 5432
    dbname   = var.rds_database_name
  })
}

resource "aws_db_subnet_group" "this" {
  name_prefix = "${local.name_prefix}-"
  subnet_ids  = module.vpc.intra_subnets
  description = "Isolated subnet group for RDS"

  tags = {
    Name = "${local.name_prefix}-db-subnet-group"
  }
}

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.5"

  identifier = "${local.name_prefix}-postgres"

  engine               = "postgres"
  engine_version       = "16.3"
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = var.rds_instance_class

  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.main.arn
  storage_type          = "gp3"

  db_name  = var.rds_database_name
  username = var.rds_master_username
  password = random_password.rds.result
  port     = 5432

  multi_az               = var.environment == "production"
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = var.environment == "production" ? 30 : 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  deletion_protection = var.environment == "production"
  skip_final_snapshot = var.environment != "production"
  final_snapshot_identifier_prefix = "${local.name_prefix}-final"

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.main.arn

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  parameters = [
    {
      name  = "log_connections"
      value = "1"
    },
    {
      name  = "log_disconnections"
      value = "1"
    },
    {
      name  = "log_checkpoints"
      value = "1"
    },
    {
      name  = "shared_preload_libraries"
      value = "pg_stat_statements"
    },
  ]

  tags = {
    Name = "${local.name_prefix}-postgres"
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name_prefix = "${local.name_prefix}-rds-mon-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
  ]

  tags = {
    Name = "${local.name_prefix}-rds-monitoring"
  }
}

# -----------------------------------------------------------------------------
# ElastiCache Redis 7
# -----------------------------------------------------------------------------
resource "aws_elasticache_subnet_group" "this" {
  name        = "${local.name_prefix}-redis"
  subnet_ids  = module.vpc.intra_subnets
  description = "Isolated subnet group for Redis"

  tags = {
    Name = "${local.name_prefix}-redis-subnet-group"
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "SOC Analyst Agent Redis cluster"

  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_clusters   = var.environment == "production" ? 3 : 1
  port                 = 6379
  parameter_group_name = aws_elasticache_parameter_group.redis.name

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.main.arn
  auth_token                 = random_password.redis_auth.result

  automatic_failover_enabled = var.environment == "production"
  multi_az_enabled           = var.environment == "production"

  snapshot_retention_limit = var.environment == "production" ? 7 : 1
  snapshot_window          = "05:00-06:00"
  maintenance_window       = "sun:06:00-sun:07:00"

  apply_immediately = var.environment != "production"

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}

resource "aws_elasticache_parameter_group" "redis" {
  family      = "redis7"
  name        = "${local.name_prefix}-redis-params"
  description = "Custom Redis 7 parameter group for SOC Analyst"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  parameter {
    name  = "notify-keyspace-events"
    value = "Ex"
  }

  tags = {
    Name = "${local.name_prefix}-redis-params"
  }
}

resource "random_password" "redis_auth" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "redis_auth" {
  name_prefix = "${local.name_prefix}-redis-auth-"
  kms_key_id  = aws_kms_key.main.arn

  tags = {
    Name = "${local.name_prefix}-redis-auth"
  }
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = aws_secretsmanager_secret.redis_auth.id
  secret_string = jsonencode({
    auth_token = random_password.redis_auth.result
    endpoint   = aws_elasticache_replication_group.redis.primary_endpoint_address
    port       = 6379
  })
}

# -----------------------------------------------------------------------------
# OpenSearch Domain (3 nodes)
# -----------------------------------------------------------------------------
resource "aws_opensearch_domain" "this" {
  domain_name    = local.name_prefix
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type            = var.opensearch_instance_type
    instance_count           = 3
    zone_awareness_enabled   = true
    dedicated_master_enabled = var.environment == "production"
    dedicated_master_type    = var.environment == "production" ? var.opensearch_master_instance_type : null
    dedicated_master_count   = var.environment == "production" ? 3 : null

    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  vpc_options {
    subnet_ids         = slice(module.vpc.intra_subnets, 0, 3)
    security_group_ids = [aws_security_group.opensearch.id]
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.opensearch_volume_size
    iops        = 3000
    throughput  = 125
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.main.arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true

    master_user_options {
      master_user_name     = var.opensearch_master_user
      master_user_password = random_password.opensearch.result
    }
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "SEARCH_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }

  tags = {
    Name = "${local.name_prefix}-opensearch"
  }
}

resource "random_password" "opensearch" {
  length           = 32
  special          = true
  override_special = "!@#$%^&*"
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
}

resource "aws_secretsmanager_secret" "opensearch" {
  name_prefix = "${local.name_prefix}-opensearch-"
  kms_key_id  = aws_kms_key.main.arn

  tags = {
    Name = "${local.name_prefix}-opensearch-creds"
  }
}

resource "aws_secretsmanager_secret_version" "opensearch" {
  secret_id = aws_secretsmanager_secret.opensearch.id
  secret_string = jsonencode({
    username = var.opensearch_master_user
    password = random_password.opensearch.result
    endpoint = aws_opensearch_domain.this.endpoint
  })
}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/aws/opensearch/${local.name_prefix}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.main.arn

  tags = {
    Name = "${local.name_prefix}-opensearch-logs"
  }
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${local.name_prefix}-opensearch-log-policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "es.amazonaws.com"
        }
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogStream",
        ]
        Resource = "${aws_cloudwatch_log_group.opensearch.arn}:*"
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# S3 – Backups bucket
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "backups" {
  bucket_prefix = "${local.name_prefix}-backups-"
  force_destroy = var.environment != "production"

  tags = {
    Name = "${local.name_prefix}-backups"
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
