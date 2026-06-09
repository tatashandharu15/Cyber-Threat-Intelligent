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
