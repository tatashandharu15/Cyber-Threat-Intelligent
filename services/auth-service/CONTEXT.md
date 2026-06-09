# Auth Service Context

## Purpose

Provides authentication, session lifecycle, and access entry points.

## APIs

- `/v1/auth/login`
- `/v1/auth/logout`
- `/v1/auth/refresh`

## Events

- consumes `user.created`
- produces `auth.login.succeeded`

## Database Tables

- `sessions`
- references `users`

## Dependencies

- `packages/shared-types`
- `packages/utils`
- `services/monitoring-service`
