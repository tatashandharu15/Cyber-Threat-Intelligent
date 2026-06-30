variable "region" {
  description = "AWS region for staging. Defaults to the primary platform region."
  type        = string
  default     = "ap-southeast-1"
}

variable "kubernetes_version" {
  description = "EKS control plane version."
  type        = string
  default     = "1.29"
}

variable "db_password" {
  description = "Aurora master password. Provide via TF_VAR_db_password or a secret manager; never commit a real value."
  type        = string
  sensitive   = true
}
