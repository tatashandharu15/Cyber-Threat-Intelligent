# Web App Context

## Purpose

Primary customer-facing application for authenticated end users.

## Pages

- login
- dashboard
- reports

## Dependencies

- `packages/ui`
- `packages/shared-types`
- `services/auth-service`
- `services/reporting-service`

## API Usage

- auth endpoints
- dashboard summary endpoints
- report retrieval endpoints

## Authentication

Uses standard user sign-in and session validation for protected routes.

## Known Issues

- Role-specific landing page logic may evolve as products diversify.

## Future Roadmap

- Add richer self-service workflows
- Add tenant personalization patterns
