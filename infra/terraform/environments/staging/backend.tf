# Remote state backend (S3 + DynamoDB lock). COMMENTED OUT so that
# `terraform init -backend=false` works for offline validation. Uncomment, fill
# in the bucket/table (provisioned out-of-band, e.g. infra/terraform global), and
# run `terraform init -migrate-state` to enable remote state for staging.
#
# terraform {
#   backend "s3" {
#     bucket         = "cti-tfstate-staging"
#     key            = "staging/terraform.tfstate"
#     region         = "ap-southeast-1"
#     dynamodb_table = "cti-tfstate-lock"
#     encrypt        = true
#   }
# }
