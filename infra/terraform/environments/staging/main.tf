# Staging environment for the SiberIndo CTI platform.
# Calls the root composition (../../) with staging-sized inputs. Node group and
# DB defaults already reflect staging in the root variables; this layer pins the
# environment name and threads the sensitive DB password through.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

module "cti" {
  source = "../../"

  env                = "staging"
  region             = var.region
  kubernetes_version = var.kubernetes_version

  db_password = var.db_password
}
