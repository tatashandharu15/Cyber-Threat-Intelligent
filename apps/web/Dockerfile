# Multi-stage build for the Next.js 15 (App Router) web frontend.
# Build context = apps/web:
#
#   docker build -t cti-web:staging apps/web
#
# Relies on `output: "standalone"` in next.config.ts, which emits a minimal
# self-contained server bundle at .next/standalone.

# --- deps ------------------------------------------------------------------
FROM node:22-alpine AS deps
WORKDIR /app
# .npmrc carries legacy-peer-deps=true (React 19 peer ranges).
COPY package.json package-lock.json .npmrc ./
RUN npm ci

# --- builder ---------------------------------------------------------------
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# Produce the standalone server bundle for the container image (gated in next.config.ts).
ENV NEXT_OUTPUT=standalone
RUN npm run build

# --- runner ----------------------------------------------------------------
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Run as the built-in unprivileged node user.
RUN chown -R node:node /app
USER node

# Standalone server + the static assets it does not inline. (This app has no
# public/ directory; if one is added, COPY it here too — Next standalone does
# not bundle public/.)
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static

EXPOSE 3000
CMD ["node", "server.js"]
