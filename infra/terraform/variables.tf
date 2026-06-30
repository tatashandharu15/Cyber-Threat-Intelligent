# Root composition variables. Environments (environments/staging) pass these in.

variable "region" {
  description = "AWS region. Primary platform region is ap-southeast-1 (Singapore)."
  type        = string
  default     = "ap-southeast-1"
}

variable "env" {
  description = "Environment name (staging, production). Used in resource names."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC. Blueprint: 10.0.0.0/16 (production VPC)."
  type        = string
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "Availability zones to spread subnets across (3 for HA)."
  type        = list(string)
  default     = ["ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"]
}

variable "kubernetes_version" {
  description = "EKS control plane version. Blueprint baseline is 1.29."
  type        = string
  default     = "1.29"
}

# --- Node group sizing (Infra Blueprint 3.2). Staging uses smaller min/max. ---

variable "node_groups" {
  description = <<-EOT
    Managed node group configuration keyed by name. Instance types follow the
    blueprint (system m6i.large, api-general m6i.xlarge, collection-workers
    c6i.2xlarge, collection-isolated c6i.xlarge, search-intensive r6i.2xlarge);
    staging shrinks min/max for cost. labels/taints carry the scheduling
    contract the Kubernetes manifests rely on (role=..., dwm-isolated taint).
  EOT
  type = map(object({
    instance_types = list(string)
    min_size       = number
    max_size       = number
    desired_size   = number
    capacity_type  = string
    labels         = map(string)
    taints = optional(map(object({
      key    = string
      value  = string
      effect = string
    })), {})
  }))
  default = {
    system = {
      instance_types = ["m6i.large"]
      min_size       = 1
      max_size       = 3
      desired_size   = 2
      capacity_type  = "ON_DEMAND"
      labels         = { role = "system" }
    }
    api-general = {
      instance_types = ["m6i.xlarge"]
      min_size       = 2
      max_size       = 6
      desired_size   = 2
      capacity_type  = "ON_DEMAND"
      labels         = { role = "api" }
    }
    collection-workers = {
      instance_types = ["c6i.2xlarge"]
      min_size       = 1
      max_size       = 4
      desired_size   = 1
      capacity_type  = "SPOT"
      labels         = { role = "collection" }
    }
    collection-isolated = {
      instance_types = ["c6i.xlarge"]
      min_size       = 1
      max_size       = 2
      desired_size   = 1
      capacity_type  = "ON_DEMAND"
      labels         = { role = "dwm-collection" }
      taints = {
        dwm = {
          key    = "dwm-isolated"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    }
    search-intensive = {
      instance_types = ["r6i.2xlarge"]
      min_size       = 1
      max_size       = 3
      desired_size   = 1
      capacity_type  = "ON_DEMAND"
      labels         = { role = "search" }
    }
  }
}

# --- Aurora PostgreSQL (Infra Blueprint 4.1). Staging = one cluster. ---

variable "db_instance_class" {
  description = "Aurora instance class. Staging uses Serverless v2 (see db_serverless)."
  type        = string
  default     = "db.serverless"
}

variable "db_engine_version" {
  description = "Aurora PostgreSQL engine version. Blueprint baseline 15.x."
  type        = string
  default     = "15.4"
}

variable "db_name" {
  description = "Initial database name. Staging holds all schemas in one DB."
  type        = string
  default     = "cti"
}

variable "db_username" {
  description = "Master DB username."
  type        = string
  default     = "cti_admin"
}

variable "db_password" {
  description = "Master DB password. Supply via TF_VAR_db_password or a secrets manager; never commit."
  type        = string
  sensitive   = true
}

# --- MSK (Infra Blueprint 4.2). ---

variable "msk_kafka_version" {
  description = "MSK Kafka version. Blueprint baseline 3.5."
  type        = string
  default     = "3.5.1"
}

variable "msk_broker_instance_type" {
  description = "MSK broker instance type. Blueprint kafka.m5.xlarge; staging smaller."
  type        = string
  default     = "kafka.m5.large"
}

variable "msk_broker_count" {
  description = "Number of MSK brokers (one per AZ)."
  type        = number
  default     = 3
}

# --- ECR repositories (Infra Blueprint 7.2). ---

variable "service_names" {
  description = "Service names that get an ECR repository (14 Go services + web)."
  type        = list(string)
  default = [
    "auth-service",
    "user-service",
    "asset-service",
    "alert-engine",
    "dlm-service",
    "clm-service",
    "dwm-service",
    "brm-service",
    "phm-service",
    "investigation-service",
    "notification-service",
    "audit-service",
    "indicator-service",
    "takedown-service",
    "web",
  ]
}
