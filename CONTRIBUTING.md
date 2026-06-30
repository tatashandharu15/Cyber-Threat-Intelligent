# Contributing

## Principles

- Keep documents concise, structured, and AI-readable
- Update source-of-truth files before implementation drifts
- Document requirements by domain, not by endpoint or function
- Record architectural change in ADRs
- Keep module ownership explicit

## Suggested Flow

1. Read `.ai/` files in order.
2. Read the relevant SRS module and ADRs.
3. Confirm roadmap and backlog alignment.
4. Implement the smallest safe change.
5. Update affected docs, registries, and knowledge files.
6. Add validation notes and operational guidance if needed.

## Protected Files

Require extra review before broad automated edits:

- `docs/adr/*`
- `docs/security/*`
- `docs/srs/SRS_MASTER.md`
- `.ai/architecture-summary.md`
- `.ai/registry/database.md`
- `.ai/registry/events.md`

## Engineering Workflow (code changes)

For changes to `apps/`, `services/`, `packages/`, or `infra/`, follow the
trunk-based, build-once-promote-many workflow. Full detail lives in
[`docs/engineering/`](docs/engineering/README.md); the short loop is:

1. **Branch** off the latest `main` — short-lived `feat/<scope>`, `fix/<scope>`, or
   `chore/<scope>` (see [branching-strategy.md](docs/engineering/branching-strategy.md)).
2. **Commit** using [Conventional Commits](docs/engineering/conventional-commits.md)
   (`type(scope): subject`). Because we squash-merge, your **PR title must be a valid
   Conventional Commit** — it becomes the commit on `main`.
3. **Open a PR.** It must pass the required checks before it can merge: `ci`
   (build/vet/test + web lint/build), `pr-title-lint`, and `security-scan`, plus a
   CODEOWNERS review (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).
4. **Squash merge** to `main`. This triggers an immutable image build
   (`ghcr.io/<owner>/cti-*:sha-<short>`) and an **auto-deploy to `dev`** (see
   [release-strategy.md](docs/engineering/release-strategy.md)).
5. **Promote to staging** (the same image, no rebuild):
   `make promote-staging VERSION=<tag>`. Soak per the SLO window.
6. **Promote to production**: `make promote-production VERSION=<tag>`. This is gated
   by a GitHub Environment **approval** (a required reviewer must approve).
7. release-please maintains the version + `CHANGELOG.md` from your commit types; see
   [semantic-versioning.md](docs/engineering/semantic-versioning.md).

If something regresses, **roll back the image** (promote a known-good tag) — never a
schema rollback — per [`docs/runbooks/rollback.md`](docs/runbooks/rollback.md).
Database migrations are **forward-only** ([migration-policy.md](docs/engineering/migration-policy.md));
the HTTP API is versioned at `/v1` ([api-versioning-policy.md](docs/engineering/api-versioning-policy.md)).
