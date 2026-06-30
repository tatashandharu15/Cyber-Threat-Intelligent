# Provider for the staging environment. Configured here (the root of this
# Terraform run) and inherited by the ../../ composition module.
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "siberindo-cti"
      Environment = "staging"
      ManagedBy   = "terraform"
    }
  }
}
