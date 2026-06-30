# Terraform — SiberIndo CTI Platform Infrastructure

Infrastructure-as-code foundation for deploying the CTI/DRP platform to AWS
`ap-southeast-1` (Singapore — data residency requirement). Follows
`docs/design/05-infrastructure-blueprint.md`.

## Layout

```
infra/terraform/
├── versions.tf            # terraform >= 1.5, aws provider ~> 5
├── providers.tf           # (no provider block — configured by the environment)
├── variables.tf           # root composition inputs (region, cidr, node groups, db, msk, ecr)
├── main.tf                # VPC + EKS + Aurora + MSK + S3 + ECR + security groups
├── outputs.tf             # cluster endpoint, ecr urls, db endpoint, msk brokers, buckets
└── environments/
    └── staging/
        ├── main.tf                  # calls ../../ as a module with staging inputs
        ├── providers.tf             # owns the aws provider (region + default tags)
        ├── variables.tf             # staging inputs (region, k8s version, db_password)
        ├── terraform.tfvars.example # copy to terraform.tfvars; secrets via env/secret-mgr
        └── backend.tf               # S3 remote state (commented placeholder)
```

The root directory is a **reusable composition**: it declares no provider, so an
environment wrapper supplies it. `environments/staging` is the actual Terraform
root you `init`/`plan`/`apply` from.

## What it provisions

| Module / Resource | Source (pinned) | Notes |
|---|---|---|
| VPC | `terraform-aws-modules/vpc/aws ~> 5.21` | public + private + db subnets across 3 AZs, single NAT (staging) |
| EKS | `terraform-aws-modules/eks/aws ~> 20.0` | cluster + 5 managed node groups: `system`, `api-general`, `collection-workers`, `collection-isolated` (tainted `dwm-isolated`), `search-intensive` |
| Aurora PostgreSQL | `terraform-aws-modules/rds-aurora/aws ~> 9.16` | one Serverless v2 cluster (prod runs 3: core/monitoring/services) |
| MSK | `aws_msk_cluster` | 3 brokers, TLS in transit, encryption at rest |
| S3 | `aws_s3_bucket` + lock/lifecycle | evidence / takedown / audit-archive with Object Lock COMPLIANCE (7y) + versioning; reports (90d) + exports (7d) lifecycle expiry |
| ECR | `aws_ecr_repository` (`for_each`) | one repo per service: 14 Go services + web; scan-on-push, immutable tags |

> Provider pinning: AWS provider is `~> 5`, so module majors are chosen to match
> (VPC 5.x, EKS 20.x, rds-aurora 9.x). Moving to VPC 6.x / EKS 21.x / aurora 10.x
> requires bumping the provider to `~> 6` first.

## Prerequisites

- Terraform >= 1.5, AWS credentials with admin-equivalent provisioning rights.
- An S3 bucket + DynamoDB lock table for remote state (provision once, then
  uncomment `environments/staging/backend.tf`).
- `TF_VAR_db_password` exported (or a secret-manager data source) — never commit
  a real password.

## Init / plan / apply order

```bash
cd infra/terraform/environments/staging

# 1. Offline validation (no cloud, no backend):
terraform init -backend=false
terraform validate

# 2. Real run — configure remote state first (uncomment backend.tf), then:
export TF_VAR_db_password='<from secret manager / Vault>'
terraform init
terraform plan  -out tfplan
terraform apply tfplan
```

Apply ordering is handled by Terraform's dependency graph: VPC → EKS / Aurora /
MSK / security groups → (S3 and ECR are independent). After `apply`, wire
`kubectl` to the new cluster and deploy the manifests:

```bash
aws eks update-kubeconfig --region ap-southeast-1 --name cti-staging
kubectl apply -k ../../../kubernetes/overlays/staging
```

## Secrets

This foundation provisions infrastructure, **not** application secrets. At
runtime:

- DB credentials, JWT RS256 keys, and the audit HMAC key are delivered to pods
  by **HashiCorp Vault** (Infra Blueprint section 6) or SealedSecrets — see
  `infra/kubernetes/base/secrets.example.yaml`.
- S3 write access uses Vault dynamic AWS credentials (1h TTL) or IRSA, not static
  keys.
- The only Terraform-time secret is `db_password`, passed via `TF_VAR_db_password`
  and stored in encrypted remote state.

## Not yet included (deliberate scope)

OpenSearch, ElastiCache Redis, Vault cluster, VPC endpoints, the DWM isolation
VPC + peering, Aurora Global Database (DR), Route 53, ACM, and WAF are described
in the blueprint and are the next layers to add on top of this foundation.
