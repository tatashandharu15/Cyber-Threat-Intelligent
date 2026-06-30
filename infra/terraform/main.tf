# =============================================================================
# SiberIndo CTI platform — root composition.
# Wires community terraform-aws-modules together into one deployable foundation
# per the Infrastructure Blueprint. An environment (environments/staging) calls
# this composition with environment-specific variables.
#
# Module versions are pinned and chosen to stay compatible with AWS provider
# ~> 5 (see versions.tf): VPC 5.21, EKS 20.x, rds-aurora 9.16.
# =============================================================================

locals {
  name = "cti-${var.env}"

  # Three private subnets per AZ tier mirror the blueprint:
  #   public  -> ALB / NAT          (10.0.1-3.0/24)
  #   private -> EKS nodes          (10.0.11-13.0/24)
  #   db      -> Aurora / MSK / OS  (10.0.21-23.0/24)
  public_subnets   = [for i, _ in var.azs : cidrsubnet(var.vpc_cidr, 8, i + 1)]
  private_subnets  = [for i, _ in var.azs : cidrsubnet(var.vpc_cidr, 8, i + 11)]
  database_subnets = [for i, _ in var.azs : cidrsubnet(var.vpc_cidr, 8, i + 21)]
}

# -----------------------------------------------------------------------------
# VPC — public + private + database subnets across 3 AZs with a single NAT for
# staging cost (blueprint prod uses one NAT per AZ).
# -----------------------------------------------------------------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.21"

  name = local.name
  cidr = var.vpc_cidr
  azs  = var.azs

  public_subnets   = local.public_subnets
  private_subnets  = local.private_subnets
  database_subnets = local.database_subnets

  create_database_subnet_group = true

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Tags required by the AWS Load Balancer Controller / EKS for subnet discovery.
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# -----------------------------------------------------------------------------
# EKS — managed control plane + the blueprint node groups (system, api-general,
# collection-workers, collection-isolated, search-intensive). Node groups carry
# the role labels and the dwm-isolated taint the Kubernetes manifests expect.
# -----------------------------------------------------------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = local.name
  cluster_version = var.kubernetes_version

  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_addons = {
    coredns            = {}
    kube-proxy         = {}
    vpc-cni            = {}
    aws-ebs-csi-driver = {}
  }

  eks_managed_node_groups = {
    for ng, cfg in var.node_groups : ng => {
      instance_types = cfg.instance_types
      min_size       = cfg.min_size
      max_size       = cfg.max_size
      desired_size   = cfg.desired_size
      capacity_type  = cfg.capacity_type
      labels         = cfg.labels
      taints         = cfg.taints
    }
  }
}

# -----------------------------------------------------------------------------
# Security group for the application tier to reach data stores (Aurora :5432,
# MSK :9092/:9094). EKS node SG is managed by the EKS module; this SG models the
# "sg-eks-nodes -> data" allowances from blueprint 2.1 for clarity.
# -----------------------------------------------------------------------------
resource "aws_security_group" "data_clients" {
  name_prefix = "${local.name}-data-clients-"
  description = "CTI app tier egress to Aurora and MSK"
  vpc_id      = module.vpc.vpc_id

  egress {
    description = "All egress (NAT)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "aurora" {
  name_prefix = "${local.name}-aurora-"
  description = "Aurora PostgreSQL — ingress from EKS nodes only"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "PostgreSQL from app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.data_clients.id, module.eks.node_security_group_id]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "msk" {
  name_prefix = "${local.name}-msk-"
  description = "MSK — ingress from EKS nodes only"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Kafka plaintext/TLS from app tier"
    from_port       = 9092
    to_port         = 9098
    protocol        = "tcp"
    security_groups = [aws_security_group.data_clients.id, module.eks.node_security_group_id]
  }

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# Aurora PostgreSQL — one staging cluster holding all schemas (prod runs 3:
# core / monitoring / services, blueprint 4.1). Serverless v2 scales to 0.5 ACU.
# -----------------------------------------------------------------------------
module "aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 9.16"

  name                        = local.name
  engine                      = "aurora-postgresql"
  engine_mode                 = "provisioned"
  engine_version              = var.db_engine_version
  database_name               = var.db_name
  master_username             = var.db_username
  master_password             = var.db_password
  manage_master_user_password = false

  vpc_id                 = module.vpc.vpc_id
  db_subnet_group_name   = module.vpc.database_subnet_group_name
  vpc_security_group_ids = [aws_security_group.aurora.id]

  # Serverless v2 capacity for staging (blueprint 11.3: scale to 0 when idle).
  serverlessv2_scaling_configuration = {
    min_capacity = 0.5
    max_capacity = 4.0
  }

  instance_class = "db.serverless"
  instances = {
    one = {}
  }

  storage_encrypted   = true
  apply_immediately   = true
  skip_final_snapshot = true
}

# -----------------------------------------------------------------------------
# MSK — 3 brokers (one per AZ), TLS in transit, encryption at rest (blueprint 4.2).
# -----------------------------------------------------------------------------
resource "aws_msk_cluster" "this" {
  cluster_name           = local.name
  kafka_version          = var.msk_kafka_version
  number_of_broker_nodes = var.msk_broker_count

  broker_node_group_info {
    instance_type   = var.msk_broker_instance_type
    client_subnets  = module.vpc.database_subnets
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}

# -----------------------------------------------------------------------------
# S3 buckets (blueprint 4.5). Evidence / takedown-packages / audit-archive use
# Object Lock in COMPLIANCE mode with 7-year (2557-day) retention + versioning.
# reports (90d) and exports (7d) are mutable with lifecycle expiry.
# -----------------------------------------------------------------------------

# --- Object-Lock (COMPLIANCE) buckets ---
locals {
  compliance_buckets = {
    evidence      = "cti-evidence-${var.env}"
    takedown      = "cti-takedown-packages-${var.env}"
    audit_archive = "cti-audit-archive-${var.env}"
  }
  expiring_buckets = {
    reports = { bucket = "cti-reports-${var.env}", expire_days = 90 }
    exports = { bucket = "cti-exports-${var.env}", expire_days = 7 }
  }
}

resource "aws_s3_bucket" "compliance" {
  for_each = local.compliance_buckets

  bucket              = each.value
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "compliance" {
  for_each = aws_s3_bucket.compliance

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "compliance" {
  for_each = aws_s3_bucket.compliance

  bucket = each.value.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 2557 # ~7 years
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance" {
  for_each = aws_s3_bucket.compliance

  bucket = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "compliance" {
  for_each = aws_s3_bucket.compliance

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Mutable buckets with lifecycle expiry (reports, exports) ---
resource "aws_s3_bucket" "expiring" {
  for_each = local.expiring_buckets

  bucket = each.value.bucket
}

resource "aws_s3_bucket_lifecycle_configuration" "expiring" {
  for_each = local.expiring_buckets

  bucket = aws_s3_bucket.expiring[each.key].id
  rule {
    id     = "expire"
    status = "Enabled"

    filter {}

    expiration {
      days = each.value.expire_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "expiring" {
  for_each = aws_s3_bucket.expiring

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------------------
# ECR — one private repository per service (blueprint 7.2). Image scan on push;
# immutable tags so a SHA tag is never overwritten.
# -----------------------------------------------------------------------------
resource "aws_ecr_repository" "services" {
  for_each = toset(var.service_names)

  name                 = "cti-${each.value}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "services" {
  for_each = aws_ecr_repository.services

  repository = each.value.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 20 tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v", "staging", "sha"]
          countType     = "imageCountMoreThan"
          countNumber   = 20
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Expire untagged after 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      }
    ]
  })
}
