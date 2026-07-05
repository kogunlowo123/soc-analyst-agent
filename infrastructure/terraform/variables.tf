# -----------------------------------------------------------------------------
# General
# -----------------------------------------------------------------------------
variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "Must be a valid AWS region identifier (e.g. us-east-1)."
  }
}

variable "environment" {
  description = "Deployment environment (development, staging, production)"
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "owner" {
  description = "Team or individual that owns these resources"
  type        = string
  default     = "soc-engineering"
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

# -----------------------------------------------------------------------------
# EKS
# -----------------------------------------------------------------------------
variable "eks_cluster_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.29"

  validation {
    condition     = can(regex("^1\\.(2[8-9]|3[0-9])$", var.eks_cluster_version))
    error_message = "Cluster version must be 1.28 or later."
  }
}

variable "eks_node_instance_types" {
  description = "Instance types for the general EKS managed node group"
  type        = list(string)
  default     = ["m6i.xlarge", "m6a.xlarge"]
}

variable "eks_spot_instance_types" {
  description = "Instance types for the spot EKS managed node group"
  type        = list(string)
  default     = ["m6i.xlarge", "m6a.xlarge", "m5.xlarge", "m5a.xlarge"]
}

variable "eks_node_min_size" {
  description = "Minimum number of nodes in the general node group"
  type        = number
  default     = 2

  validation {
    condition     = var.eks_node_min_size >= 1
    error_message = "Minimum node count must be at least 1."
  }
}

variable "eks_node_max_size" {
  description = "Maximum number of nodes in the general node group"
  type        = number
  default     = 10

  validation {
    condition     = var.eks_node_max_size >= 2
    error_message = "Maximum node count must be at least 2."
  }
}

variable "eks_node_desired_size" {
  description = "Desired number of nodes in the general node group"
  type        = number
  default     = 3

  validation {
    condition     = var.eks_node_desired_size >= 1
    error_message = "Desired node count must be at least 1."
  }
}

# -----------------------------------------------------------------------------
# RDS PostgreSQL
# -----------------------------------------------------------------------------
variable "rds_instance_class" {
  description = "Instance class for the RDS PostgreSQL database"
  type        = string
  default     = "db.r6g.large"

  validation {
    condition     = can(regex("^db\\.", var.rds_instance_class))
    error_message = "Must be a valid RDS instance class (e.g. db.r6g.large)."
  }
}

variable "rds_allocated_storage" {
  description = "Initial allocated storage in GiB for RDS"
  type        = number
  default     = 100

  validation {
    condition     = var.rds_allocated_storage >= 20
    error_message = "Allocated storage must be at least 20 GiB."
  }
}

variable "rds_max_allocated_storage" {
  description = "Maximum allocated storage in GiB for RDS autoscaling"
  type        = number
  default     = 500

  validation {
    condition     = var.rds_max_allocated_storage >= 100
    error_message = "Maximum allocated storage must be at least 100 GiB."
  }
}

variable "rds_database_name" {
  description = "Name of the default PostgreSQL database"
  type        = string
  default     = "soc_analyst"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,62}$", var.rds_database_name))
    error_message = "Database name must start with a letter and contain only lowercase letters, numbers, and underscores."
  }
}

variable "rds_master_username" {
  description = "Master username for the RDS instance"
  type        = string
  default     = "soc_admin"
  sensitive   = true

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{2,62}$", var.rds_master_username))
    error_message = "Username must start with a letter and be 3-63 characters long."
  }
}

# -----------------------------------------------------------------------------
# ElastiCache Redis
# -----------------------------------------------------------------------------
variable "redis_node_type" {
  description = "Node type for the ElastiCache Redis cluster"
  type        = string
  default     = "cache.r6g.large"

  validation {
    condition     = can(regex("^cache\\.", var.redis_node_type))
    error_message = "Must be a valid ElastiCache node type (e.g. cache.r6g.large)."
  }
}

# -----------------------------------------------------------------------------
# OpenSearch
# -----------------------------------------------------------------------------
variable "opensearch_instance_type" {
  description = "Instance type for OpenSearch data nodes"
  type        = string
  default     = "r6g.large.search"

  validation {
    condition     = can(regex("\\.search$", var.opensearch_instance_type))
    error_message = "Must be a valid OpenSearch instance type ending in .search."
  }
}

variable "opensearch_master_instance_type" {
  description = "Instance type for OpenSearch dedicated master nodes"
  type        = string
  default     = "r6g.large.search"

  validation {
    condition     = can(regex("\\.search$", var.opensearch_master_instance_type))
    error_message = "Must be a valid OpenSearch instance type ending in .search."
  }
}

variable "opensearch_volume_size" {
  description = "EBS volume size in GiB for each OpenSearch data node"
  type        = number
  default     = 100

  validation {
    condition     = var.opensearch_volume_size >= 20 && var.opensearch_volume_size <= 16384
    error_message = "Volume size must be between 20 and 16384 GiB."
  }
}

variable "opensearch_master_user" {
  description = "Master username for OpenSearch fine-grained access control"
  type        = string
  default     = "soc_admin"
  sensitive   = true
}
