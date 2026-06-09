# Mobile App Context

## Purpose

Mobile experience for lightweight access, notifications, and field-friendly workflows.

## Pages

- login
- dashboard summary
- alerts
- report status

## Dependencies

- `packages/shared-types`
- `services/auth-service`
- `services/monitoring-service`

## API Usage

- auth
- alert summary
- report status

## Authentication

Uses secure mobile session or token handling with reduced-surface interactions.

## Known Issues

- Offline and degraded-network behavior are not yet detailed.

## Future Roadmap

- Add push-oriented alert handling
- Add offline-safe status summaries
