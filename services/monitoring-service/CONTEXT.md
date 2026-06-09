# Monitoring Service Context

## Purpose

Provides health visibility, alerts, and operational telemetry workflows.

## APIs

- `/v1/health`
- `/v1/alerts`
- `/v1/monitoring-targets`

## Events

- produces `alert.triggered`
- consumes platform and auth activity signals

## Database Tables

- `audit_logs`
- monitoring target metadata
