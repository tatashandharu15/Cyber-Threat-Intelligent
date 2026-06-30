output "region" {
  description = "AWS region the platform is deployed into."
  value       = var.region
}

output "vpc_id" {
  description = "VPC ID."
  value       = module.vpc.vpc_id
}

output "cluster_name" {
  description = "EKS cluster name."
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS API server endpoint."
  value       = module.eks.cluster_endpoint
}

output "db_endpoint" {
  description = "Aurora writer endpoint (DATABASE_URL host)."
  value       = module.aurora.cluster_endpoint
}

output "db_reader_endpoint" {
  description = "Aurora reader endpoint."
  value       = module.aurora.cluster_reader_endpoint
}

output "msk_bootstrap_brokers" {
  description = "MSK TLS bootstrap broker connection string (KAFKA_BROKERS)."
  value       = aws_msk_cluster.this.bootstrap_brokers_tls
}

output "ecr_repository_urls" {
  description = "Map of service name -> ECR repository URL."
  value       = { for name, repo in aws_ecr_repository.services : name => repo.repository_url }
}

output "s3_bucket_names" {
  description = "Object-Lock and lifecycle S3 bucket names."
  value = merge(
    { for k, b in aws_s3_bucket.compliance : k => b.id },
    { for k, b in aws_s3_bucket.expiring : k => b.id },
  )
}
