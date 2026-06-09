# Package Catalog

## Shared Libraries

### ui

- Purpose: shared UI primitives, design tokens, and reusable presentation patterns
- Ownership: frontend-platform
- Dependencies: shared-types
- Usage Rules: update UI guide before changing reusable patterns; avoid product-specific logic

### shared-types

- Purpose: canonical cross-layer contracts and types
- Ownership: platform-team
- Dependencies: minimal or none
- Usage Rules: use for shared API contracts; avoid embedding runtime logic

### utils

- Purpose: low-level reusable helpers
- Ownership: platform-team
- Dependencies: keep minimal
- Usage Rules: allow only truly cross-cutting helpers; do not turn into a dumping ground
