# Service Catalog

## Auth Service

- Purpose: Own authentication, session lifecycle, and access entry points
- Owner: platform-team
- Dependencies: shared-types, utils, monitoring-service
- Consumers: web, admin, mobile
- APIs: `/v1/auth/login`, `/v1/auth/logout`, `/v1/auth/refresh`
- Events: consumes `user.created`, produces `auth.login.succeeded`
- Database Tables: `sessions`, references `users`
- SLA: 99.9% availability target for login and token refresh

## Monitoring Service

- Purpose: Own health state, alerts, audit signals, and operational telemetry
- Owner: sre-team
- Dependencies: utils, infra
- Consumers: admin dashboard, reporting, on-call workflows
- APIs: `/v1/health`, `/v1/alerts`, `/v1/monitoring-targets`
- Events: produces `alert.triggered`, consumes auth and platform signals
- Database Tables: `audit_logs`, monitoring target metadata
- SLA: 99.9% visibility target for active production monitoring

## Reporting Service

- Purpose: Own report generation, retrieval, and export metadata
- Owner: data-team
- Dependencies: shared-types, monitoring-service
- Consumers: web, admin, downstream operational workflows
- APIs: `/v1/reports`, `/v1/reports/{id}`
- Events: produces `report.generated`
- Database Tables: `reports`
- SLA: 99.5% successful report processing target within agreed latency windows
