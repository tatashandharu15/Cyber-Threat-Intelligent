# monorepo-ai-workspace

A reusable GitHub repository template for long-term AI-assisted software development in monorepo environments.

## Purpose

This repository is a workspace template, not a software product. It gives humans and AI coding agents a shared operating model, compact context files, and durable architecture governance.

## First Onboarding Step

Read `START_HERE.md` for the fastest orientation path across purpose, hierarchy, lifecycle, governance, and AI workflow.

## Optimized For

- Trae
- Claude Code
- Cursor
- Windsurf
- Gemini CLI
- OpenAI Codex
- Human developers

## Primary Goals

- Prevent AI context loss
- Reduce token consumption
- Maintain architecture consistency
- Keep requirements organized
- Improve collaboration between humans and AI
- Scale from MVP to enterprise systems

## Required Reading Order For AI

1. `.ai/project-overview.md`
2. `.ai/business-context.md`
3. `.ai/architecture-summary.md`
4. `.ai/tech-stack.md`
5. `.ai/coding-standards.md`
6. `.ai/ai-rules.md`
7. `PROJECT_OPERATING_SYSTEM.md`
8. `context/task-entrypoints.md`
9. `.ai/current-sprint.md`
10. `.ai/registry/modules.md`
11. `.ai/registry/routes.md`
12. `.ai/registry/database.md`
13. `.ai/registry/events.md`
14. Relevant `product/`, `docs/srs/`, `docs/adr/`, `.ai/modules/`, and `docs/specs/` files

## How Humans Work

- Define strategy in `product/`
- Convert intent into formal specifications in `docs/`
- Break execution into work items in `tasks/`
- Build solutions in `apps/`, `services/`, `packages/`, and `infra/`
- Keep AI summaries and registries synchronized as the system changes

## How AI Agents Work

- Read the short-form context layer first
- Use registries to find module, route, schema, and event ownership fast
- Use SRS documents as the domain contract
- Use ADRs to understand protected architectural decisions
- Make the smallest safe change and update source-of-truth docs

## Recommended Development Lifecycle

1. Capture business intent in `product/vision.md` and `docs/brd/`
2. Define product scope in `docs/prd/`
3. Organize requirements by domain in `docs/srs/`
4. Record major decisions in `docs/adr/`
5. Plan execution in `tasks/`
6. Implement in the monorepo structure
7. Update AI context, registries, and knowledge files
8. Validate, document operations, and ship

## Context Management Strategy

- `.ai/` stores concise AI-readable memory
- `docs/` stores formal specifications and governance
- `knowledge/` stores long-term domain memory
- `context/` stores compressed summaries for large systems
- `tasks/` stores execution-ready work packages for humans and AI

## Official AI Reading Hierarchy

- Level 1: `.ai/`
- Level 2: `product/`
- Level 3: `docs/srs/`
- Level 4: `docs/specs/`
- Level 5: `apps/`, `services/`, `packages/`

## Why This Hierarchy Reduces Token Usage

- Load the smallest high-signal summaries first
- Read product intent before technical detail
- Read stable module contracts before feature-level delivery guidance
- Read implementation only after requirements and constraints are clear
- Avoid unrelated code and historical detail unless the task requires it

## V2 Enterprise Additions

- `.ai/memory/`: long-term memory for decisions, known problems, lessons learned, and technical debt
- `docs/specs/`: feature specifications bridging SRS and implementation
- `docs/rfc/`: RFC workflow before ADR and implementation
- `docs/ownership/`: explicit ownership, reviewers, stakeholders, and escalation paths
- `docs/database/tables/`: detailed table knowledge, while the registry stays lightweight
- `docs/ui-guide/design-system/`, `wireframes/`, `screens/`, `flows/`: expanded UI/UX operating system
- `product/discovery/`, `research/`, `competitors/`, `feedback/`: discovery evidence connected to roadmap, PRD, and SRS
- `evaluations/`: prompt, RAG, benchmark, dataset, and cost-efficiency evaluation assets

## V3 Enterprise Operating System

- `START_HERE.md`: single onboarding entrypoint for humans and AI agents
- `PROJECT_OPERATING_SYSTEM.md`: master operating guide for humans and AI agents
- `docs/governance/`: source-of-truth, lifecycle, review, change, exception, DoD, and quality gate framework
- `docs/traceability/`: requirement-to-code-to-deployment mapping
- `docs/observability/`: logging, metrics, tracing, alerts, SLO/SLI, and incident standards
- `agents/`: multi-agent role definitions and collaboration workflow
- `handoff/`: structured transfer templates between humans and AI agents
- `checklists/`: execution, readiness, done, release, security, UI, AI, and database checklists
- `services/CATALOG.md`, `packages/CATALOG.md`, and service/package `CONTEXT.md` files: compact implementation catalogs

## V4 Finalization Layer

- `docs/testing/`: testing architecture, test data, and test matrix guidance
- `tests/unit/`, `tests/integration/`, `tests/e2e/`, `tests/performance/`, `tests/security/`: test-layer structure
- `docs/deployment/environment-strategy.md`, `deployment-governance.md`, `rollback-strategy.md`, `production-readiness.md`: environment and release operating model
- `.meta/`: machine-readable repository metadata for AI agents and automation
- `.github/workflows/`: GitHub Actions templates for docs, architecture, security, checklist, and traceability enforcement
- `docs/governance/documentation-enforcement.md`, `repository-health-dashboard.md`, `final-scorecard.md`: enforcement and maturity tracking
- `docs/architecture/v4-review.md`: remaining gap and risk review

## Context Optimization Rules

- Read `.ai/project-overview.md`, `.ai/ai-rules.md`, and relevant registries first
- Read only the relevant product, SRS, and spec files for the active task
- Use `context/reading-hierarchy.md` and `context/context-optimization.md` before exploring large code areas
- Prefer module summaries and ownership docs over repository-wide scanning
- Update summaries, memory files, and registries when implementation meaning changes

## Complete Folder Tree

```text
monorepo-ai-workspace/
|- .github/
|  \- workflows/
|- .meta/
|- agents/
|- .ai/
|  |- memory/
|  |- registry/
|  \- modules/
|- .claude/
|- .cursor/
|  \- rules/
|- .trae/
|- apps/
|  |- admin/
|  |- mobile/
|  \- web/
|- checklists/
|- context/
|- docs/
|  |- adr/
|  |- api/
|  |- architecture/
|  |- brd/
|  |- database/
|  |  \- tables/
|  |- deployment/
|  |- governance/
|  |- observability/
|  |- ownership/
|  |- prd/
|  |- rfc/
|  |- runbooks/
|  |- security/
|  |- specs/
|  |  |- auth/
|  |  |- dashboard/
|  |  |- monitoring/
|  |  \- reporting/
|  |- srs/
|  |  |- functional-requirements/
|  |  |- non-functional-requirements/
|  |  \- modules/
|  |     |- auth/
|  |     |- dashboard/
|  |     |- monitoring/
|  |     |- reporting/
|  |     \- user/
|  |- testing/
|  |- traceability/
|  \- ui-guide/
|     |- design-system/
|     |- flows/
|     |- screens/
|     |- wireframes/
|     \- components/
|- evaluations/
|  |- benchmarks/
|  |- datasets/
|  |- prompts/
|  \- rag/
|- infra/
|  |- docker/
|  |- kubernetes/
|  \- terraform/
|- handoff/
|- knowledge/
|- packages/
|  |- shared-types/
|  |- ui/
|  \- utils/
|- product/
|  |- competitors/
|  |- discovery/
|  |- feedback/
|  \- research/
|- prompts/
|  \- project/
|- START_HERE.md
|- PROJECT_OPERATING_SYSTEM.md
|- services/
|  |- auth-service/
|  |- monitoring-service/
|  \- reporting-service/
|- tasks/
|- tests/
\- workflows/
```

## Major Sections

- `.ai/`: token-efficient project memory for AI systems
- `docs/`: BRD, PRD, SRS, architecture, ADRs, API, database, security, deployment, runbooks, and UI guide
- `docs/governance/`, `docs/traceability/`, `docs/observability/`: enterprise control layers for process, traceability, and operations
- `docs/testing/`: testing architecture and validation standards
- `product/`: vision, personas, roadmap, and success metrics
- `tasks/`: backlog and execution templates
- `prompts/`: role prompts for specialized AI contributors
- `workflows/`: repeatable operating procedures
- `knowledge/`: durable business and technical memory
- `context/`: compressed summaries for large repositories
- `evaluations/`: AI quality, cost, grounding, and benchmark evaluation assets
- `agents/`: multi-agent role and collaboration system
- `handoff/`: transfer templates for incomplete or cross-role work
- `checklists/`: actionable gates for readiness, execution, release, and review
- `.meta/`: machine-readable metadata for automation and AI efficiency
- `.github/workflows/`: automation templates for repository governance
- `apps/`, `services/`, `packages/`, `infra/`: monorepo execution layers
