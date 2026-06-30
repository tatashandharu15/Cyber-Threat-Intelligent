# SiberIndo CTI — MVP backend developer tasks.
#
# The repo is a Go multi-module workspace (see go.work). Build/test/vet iterate
# over every module so a single command checks the whole platform.

MODULES := packages/shared-types packages/utils \
	services/auth-service services/user-service services/asset-service \
	services/alert-engine services/dlm-service services/clm-service \
	services/dwm-service services/brm-service services/phm-service \
	services/investigation-service services/notification-service services/audit-service \
	services/indicator-service services/takedown-service \
	services/reporting-service services/attack-reference-service \
	services/collection-adapter-manager services/role-service

COMPOSE := docker compose -f infra/docker/docker-compose.yml

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: ## Start local infrastructure (Postgres, Kafka, Redis)
	$(COMPOSE) up -d

.PHONY: down
down: ## Stop local infrastructure
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop infra and delete volumes
	$(COMPOSE) down -v

.PHONY: build
build: ## Build every module
	@for m in $(MODULES); do echo "== build $$m =="; (cd $$m && go build ./...) || exit 1; done

.PHONY: vet
vet: ## go vet every module
	@for m in $(MODULES); do echo "== vet $$m =="; (cd $$m && go vet ./...) || exit 1; done

.PHONY: test
test: ## Run unit tests in every module
	@for m in $(MODULES); do echo "== test $$m =="; (cd $$m && go test ./...) || exit 1; done

.PHONY: test-integration
test-integration: ## Run integration tests (requires `make up`)
	@for m in $(MODULES); do echo "== itest $$m =="; (cd $$m && go test -tags=integration ./...) || exit 1; done

.PHONY: tidy
tidy: ## go mod tidy every module
	@for m in $(MODULES); do echo "== tidy $$m =="; (cd $$m && go mod tidy) || exit 1; done

.PHONY: seed
seed: ## Seed the demo tenant/user (tenant=demo, analyst@demo.siberindo.io / Demo!Passw0rd)
	cd services/auth-service && go run ./cmd/seed

.PHONY: run-auth
run-auth: ## Run the Auth service (port 8081)
	cd services/auth-service && HTTP_PORT=8081 go run ./cmd/server

.PHONY: run-user
run-user: ## Run the User service (port 8082)
	cd services/user-service && HTTP_PORT=8082 go run ./cmd/server

.PHONY: run-asset
run-asset: ## Run the Asset service (port 8083)
	cd services/asset-service && HTTP_PORT=8083 go run ./cmd/server

.PHONY: run-alert
run-alert: ## Run the Alert Engine (port 8084)
	cd services/alert-engine && HTTP_PORT=8084 go run ./cmd/server

.PHONY: run-dlm
run-dlm: ## Run the DLM service (port 8085)
	cd services/dlm-service && HTTP_PORT=8085 go run ./cmd/server

.PHONY: run-clm
run-clm: ## Run the CLM service (port 8086)
	cd services/clm-service && HTTP_PORT=8086 go run ./cmd/server

.PHONY: run-dwm
run-dwm: ## Run the DWM service (port 8087)
	cd services/dwm-service && HTTP_PORT=8087 go run ./cmd/server

.PHONY: run-brm
run-brm: ## Run the BRM service (port 8088)
	cd services/brm-service && HTTP_PORT=8088 go run ./cmd/server

.PHONY: run-phm
run-phm: ## Run the PHM service (port 8089)
	cd services/phm-service && HTTP_PORT=8089 go run ./cmd/server

.PHONY: run-investigation
run-investigation: ## Run the Investigation service (port 8090)
	cd services/investigation-service && HTTP_PORT=8090 go run ./cmd/server

.PHONY: run-notification
run-notification: ## Run the Notification Center (port 8091)
	cd services/notification-service && HTTP_PORT=8091 go run ./cmd/server

.PHONY: run-audit
run-audit: ## Run the Audit Log service (port 8092)
	cd services/audit-service && HTTP_PORT=8092 go run ./cmd/server

.PHONY: run-indicator
run-indicator: ## Run the Indicator Management service (port 8093)
	cd services/indicator-service && HTTP_PORT=8093 go run ./cmd/server

.PHONY: run-takedown
run-takedown: ## Run the Takedown service (port 8094)
	cd services/takedown-service && HTTP_PORT=8094 go run ./cmd/server

.PHONY: run-reporting
run-reporting: ## Run the Reporting service (port 8095)
	cd services/reporting-service && HTTP_PORT=8095 go run ./cmd/server

.PHONY: run-attack
run-attack: ## Run the ATT&CK Reference service (port 8096)
	cd services/attack-reference-service && HTTP_PORT=8096 go run ./cmd/server

.PHONY: run-collection
run-collection: ## Run the Collection Adapter Manager (port 8097)
	cd services/collection-adapter-manager && HTTP_PORT=8097 go run ./cmd/server

.PHONY: run-role
run-role: ## Run the Role service (port 8098)
	cd services/role-service && HTTP_PORT=8098 go run ./cmd/server

# ---------------------------------------------------------------------------
# Release & promotion (build-once-promote-many).
#
# Images are built once per commit and promoted UNCHANGED across environments.
# Promotion re-points an environment at an existing image tag via the
# promote.yml GitHub Actions workflow (no rebuild). VERSION is the image tag to
# promote, e.g. a short SHA `sha-1a2b3c4` or a release semver `v1.2.3`.
# See docs/engineering/release-strategy.md and cicd-pipeline.md.
# ---------------------------------------------------------------------------

# Guard: every promote target requires VERSION=<tag>. Prints usage and fails
# (exit 2) if missing, so `make promote-staging` alone does not silently no-op.
.PHONY: require-version
require-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required."; \
		echo "Usage: make $(MAKECMDGOALS) VERSION=<image-tag>   (e.g. VERSION=v1.2.3 or VERSION=sha-1a2b3c4)"; \
		exit 2; \
	fi

.PHONY: promote-dev
promote-dev: require-version ## Promote an image tag to dev (break-glass; dev normally auto-deploys). Usage: make promote-dev VERSION=<tag>
	gh workflow run promote.yml -f target=dev -f version=$(VERSION)

.PHONY: promote-staging
promote-staging: require-version ## Promote an image tag to staging. Usage: make promote-staging VERSION=<tag>
	gh workflow run promote.yml -f target=staging -f version=$(VERSION)

.PHONY: promote-production
promote-production: require-version ## Promote an image tag to production (requires Environment approval). Usage: make promote-production VERSION=<tag>
	gh workflow run promote.yml -f target=production -f version=$(VERSION)

.PHONY: release-notes
release-notes: ## Show the latest GitHub Release notes (or VERSION=<tag> for a specific release)
	gh release view $(VERSION)

.PHONY: changelog
changelog: ## Pointer to the generated changelog
	@echo "Changelog is maintained by release-please at ./CHANGELOG.md"
	@echo "Releases: https://github.com/<owner>/cti/releases  (or: make release-notes)"
	@echo "Release process: docs/engineering/release-strategy.md"
