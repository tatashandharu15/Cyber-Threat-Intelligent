# SiberIndo CTI — MVP Backend Developer Guide

This repository contains the implementation of the CTI/DRP platform MVP backend, a
Go multi-module workspace (`go.work`) of five services plus two shared packages,
backed by PostgreSQL (multi-schema, row-level security), Kafka, and Redis.

## Architecture at a glance

```
                          Kong API Gateway (infra/kong/kong.yml)
                                       │
   ┌──────────┬──────────┬────────────┼──────────────────────────────┐
   ▼          ▼          ▼            ▼                                │
 auth(8081) user(8082) asset(8083)  alert(8084)                       │
   │          │          │            ▲                               │
   │          │          │            │  finding.escalated.{module}   │
   │          │          │            │      (via Kafka)              │
   │          │          │     ┌───────┴───────┬───────┬───────┬──────┤
   │          │          │   dlm(8085) clm(8086) dwm(8087) brm(8088) phm(8089)
   └──────────┴──────────┴───────────── PostgreSQL ────────────────────┘
     core_platform   platform_services   monitoring_{dlm,clm,dwm,brm,phm}

   All 5 detection modules: finding.created/escalated.{module} → Alert Engine → alert.created
```

| Service | Port | Schema | Responsibility |
|---|---|---|---|
| auth-service | 8081 | core_platform | Login, MFA (TOTP), JWT issuance, sessions; owns identity DDL |
| user-service | 8082 | core_platform | User CRUD, role assignment, directory linkage |
| asset-service | 8083 | core_platform | Asset registry, brand-keyword approval gate, criticality |
| alert-engine | 8084 | platform_services | Consumes all `finding.escalated.*`, evaluates rules, writes alerts, emits `alert.created` |
| dlm-service | 8085 | monitoring_dlm | Data-leak findings, immutable evidence; defanged content URLs |
| clm-service | 8086 | monitoring_clm | Credential-leak findings; masked-only (CLM-BR-001), cleartext forces ≥high |
| dwm-service | 8087 | monitoring_dwm | Dark-web findings; no infra IDs, threat-actor profiles (no auto-attribution), network-access forces ≥high |
| brm-service | 8088 | monitoring_brm | Brand findings; similarity score + algorithm version, takedown initiation |
| phm-service | 8089 | monitoring_phm | Phishing findings; defanged URLs (NOT NULL), campaigns, indicators (TLP), immutable SSL certs, urgency promotion |
| investigation-service | 8090 | platform_services | Investigations + linked findings + immutable timeline; consumes `alert.created` into an inbox |
| notification-service | 8091 | platform_services | Notifications + preferences; consumes `alert.created`; high/critical always notified (no opt-out) |
| audit-service | 8092 | platform_services | Tamper-evident `audit_events` (HMAC + immutable); consumes `audit.event.written`; write/query/verify |
| indicator-service | 8093 | platform_services | Central indicator registry; dedup upsert `(tenant,type,value)`, TLP marking; produces `indicator.created` |
| takedown-service | 8094 | platform_services | Takedown requests + immutable event chain; state machine; produces `takedown.requested` / `takedown.status.updated` |
| reporting-service | 8095 | platform_services | Report requests; produces `report.requested`, consumes it in a worker, produces `report.completed` |
| attack-reference-service | 8096 | platform_services | Global MITRE ATT&CK technique reference (no RLS); sync + query; seeded on boot; no Kafka |
| collection-adapter-manager | 8097 | platform_services | Collection adapter registry + health; consumes `collection.job.completed`/`failed`; immutable run log |
| role-service | 8098 | core_platform | RBAC management (roles/permissions/assignments) over the identity tables; system-role immutability; no Kafka |

All five detection services share one pattern (`internal/{config,domain,store,service,api}` + `cmd/server`),
publish `finding.created/escalated.{module}`, and store immutable evidence + finding history.

Shared packages: `packages/shared-types` (enums, event schemas, error codes) and
`packages/utils` (config, db+RLS, kafka, jwt/auth, httpx, logging, server, audit).

## Prerequisites

- Go 1.25+
- Docker + Docker Compose

## Quickstart

```bash
# 1. Start infrastructure (Postgres on :5433, Kafka on :9092, Redis on :6379)
make up

# 2. Seed a demo tenant + analyst user (also runs identity migrations)
make seed
#   tenant=demo  user=analyst@demo.siberindo.io  password=Demo!Passw0rd

# 3. Run services (each in its own terminal; migrations run automatically on start)
make run-auth      # :8081
make run-alert     # :8084
make run-dlm       # :8085   (also: run-clm :8086, run-dwm :8087, run-brm :8088, run-phm :8089)
# (make run-user :8082, make run-asset :8083 as needed)
```

### Exercise the event-driven flow

```bash
# Login
TOKEN=$(curl -s -X POST localhost:8081/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"tenant_slug":"demo","email":"analyst@demo.siberindo.io","password":"Demo!Passw0rd"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["token"])')

# Create an alert rule (fires on high/critical DLM findings)
curl -s -X POST localhost:8084/v1/alert-rules -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"High+ DLM","source_module":"dlm","conditions":{"severity":["high","critical"],"confidence_score_min":0.5}}'

# Create a finding, then escalate it -> Kafka -> Alert Engine auto-creates an alert
FID=$(curl -s -X POST localhost:8085/v1/dlm/findings -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"finding_type":"credential_reference","title":"Creds on paste","severity":"high","confidence_score":0.9,"dedup_key":"demo-1"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -X POST localhost:8085/v1/dlm/findings/$FID/escalate -H "Authorization: Bearer $TOKEN"

# The alert appears within ~2s
curl -s localhost:8084/v1/alerts -H "Authorization: Bearer $TOKEN"
```

## Common tasks

```bash
make build              # build every module
make test               # unit tests across every module
make vet                # go vet across every module
make tidy               # go mod tidy across every module
make down               # stop infrastructure
make clean              # stop infrastructure and delete the Postgres volume
```

## Design decisions worth knowing

- **Multi-tenancy is enforced in the database.** Services connect as the
  non-superuser `cti` role; every tenant-scoped table has `FORCE ROW LEVEL
  SECURITY` with a `tenant_id = current_setting('app.current_tenant_id')` policy.
  All tenant-scoped queries run inside `database.DB.WithTenant`, which sets that
  GUC per transaction. RLS cannot be bypassed by application code.
- **Bounded contexts don't share foreign keys.** Cross-context references
  (`asset_id`, `created_by`, `source_finding_id`, …) are plain UUID columns. Hard
  FKs exist only within a single service's own tables.
- **Evidence and finding history are immutable.** A `prevent_mutation()` trigger
  blocks UPDATE/DELETE; only INSERT is allowed (chain of custody).
- **Threat URLs are stored defanged.** DLM rejects non-`hXXp(s)://` URLs in the
  service layer and via a DB CHECK constraint.
- **Auth/secrets are dev-grade locally.** JWTs are HS256 with a shared secret and
  MFA secrets live in the DB; the Security Blueprint specifies RS256 + Vault for
  production. Swapping is isolated to `packages/utils/auth` and Vault wiring.
- **Kafka topics auto-create in dev.** The producer sets
  `AllowAutoTopicCreation`; production pre-provisions topics on MSK.

## Verified behavior

The following were validated against live infrastructure:

- Login + JWT issuance + RBAC permission claims.
- **All five detection modules** (DLM/CLM/DWM/BRM/PHM): finding create → escalate →
  `finding.escalated.{module}` → Alert Engine consumes → alert created →
  `alert.created` → acknowledge. End-to-end latency ~1.5s per module.
- Mandatory severity elevation: a CLM `cleartext_credential` and a DWM
  `network_access_sale` created as `medium` are both forced to `high` before alerting.
- RLS: queries return 0 rows with no/incorrect tenant context, correct rows with
  the right context — even as the table-owning role.
- Immutability: UPDATE and DELETE on evidence raise the trigger exception.
- Defanged-URL rule: a live `https://` content/phishing URL is rejected with 400.

## Frontend (apps/web — analyst workbench)

Next.js 15 / React 19 / TypeScript / Tailwind v3.4 / shadcn-style UI / TanStack Query + Table / Recharts.
It talks to the **real** backend through same-origin proxy rewrites in `apps/web/next.config.ts`
(`/api/<service>/*` → `${BACKEND_HOST:-http://localhost}:<port>/v1/...`) — no mocks, no CORS.

```bash
make up && make seed           # infra + demo user
make run-auth                  # + run-alert, run-dlm, ... (whichever pages you want data for)
cd apps/web && npm install      # first time (.npmrc sets legacy-peer-deps for React 19)
npm run dev                     # http://localhost:3000 (use PORT=3100 npm run dev if 3000 is taken)
npm run lint && npm run build   # both green
```

Pages: Dashboard, Findings (DLM/CLM/DWM/BRM/PHM), Investigation (+detail), Indicators, Takedowns
(+detail), Notifications, Audit, Assets. Auth = JWT in localStorage; the sidebar and action buttons
are RBAC-gated from `/api/auth/me` permissions.

See `docs/design/` for the full architecture, database, API, UI, infrastructure,
and security blueprints this implementation follows.
