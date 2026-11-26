# Convenience targets. Everything here is also available as npm scripts or plain docker compose.
COMPOSE = docker compose --env-file deploy/.env

.PHONY: help install setup certs dev lint test build smoke demo-panel check up down logs ps images jenkins-up jenkins-down jenkins-logs

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-15s %s\n", $$1, $$2}'

install: ## Install dependencies (exact versions from the lockfile)
	npm ci

setup: ## Create ./secrets and a local .env (keeps existing secrets)
	node scripts/gen-secrets.mjs
	@test -f deploy/.env || cp deploy/.env.example deploy/.env

certs: ## Generate a local self-signed TLS certificate if one is not present
	@DOMAIN=$$(sed -n 's/^DOMAIN=//p' deploy/.env 2>/dev/null | head -n1); \
	if [ ! -f deploy/nginx/certs/server.crt ]; then sh deploy/nginx/gen-local-cert.sh "$${DOMAIN:-localhost}"; fi

dev: ## Run authority, API and Vite dev server (needs MongoDB on localhost)
	npm run dev

lint: ## ESLint
	npm run lint

test: ## Unit and integration tests (crypto, authority, API, client)
	npm test

build: ## Build the web client
	npm run build

smoke: ## End-to-end test against running services (set BASE_URL or API_URL/AUTHORITY_URL)
	npm run smoke

demo-panel: ## Self-running browser demo of Swagger/Postman/webhooks/HTTPS/Nginx
	npm run demo:panel

check: lint test build ## Everything CI runs before the image builds
	npm run audit:prod

up: setup certs ## Build images and start the full stack with TLS
	$(COMPOSE) up -d --build

down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) down

logs: ## Follow service logs
	$(COMPOSE) logs -f --tail 100

ps: ## Show container status and health
	$(COMPOSE) ps

images: ## Build the three images without starting them
	$(COMPOSE) build

jenkins-up: ## Start Dockerized Jenkins (http://localhost:8080)
	docker compose -f deploy/jenkins/docker-compose.yml up -d --build

jenkins-down: ## Stop Dockerized Jenkins
	docker compose -f deploy/jenkins/docker-compose.yml down

jenkins-logs: ## Follow Jenkins controller logs
	docker compose -f deploy/jenkins/docker-compose.yml logs -f
