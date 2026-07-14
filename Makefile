# Makefile for mproxy — HTTP CONNECT proxy

# Variables
APP_NAME := mproxy
HOST := $(shell grep '^HOST=' .env 2>/dev/null | cut -d '=' -f 2)

# Default target
.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help message
	@echo "$(APP_NAME) - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the application
	@echo "Building $(APP_NAME)..."
	@go build -o $(APP_NAME) .
	@echo "Build complete: ./$(APP_NAME)"

.PHONY: build-linux
build-linux: ## Build for Linux
	@echo "Building $(APP_NAME) for Linux..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(APP_NAME)-linux .
	@echo "Build complete: ./$(APP_NAME)-linux"

.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	@go test -v -race -count=1 ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: certs
certs: ## Generate self-signed TLS certificates
	@echo "Generating certificates..."
	@mkdir -p certs
	@openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout certs/privkey.pem -out certs/fullchain.pem \
		-days 365 -subj "/CN=localhost"
	@echo "Certificates generated: certs/"

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -f $(APP_NAME) $(APP_NAME)-linux coverage.out coverage.html
	@echo "Clean complete"

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(APP_NAME):latest .

.PHONY: docker-run
docker-run: ## Run Docker container locally
	@echo "Running Docker container..."
	@docker compose up -d

.PHONY: docker-stop
docker-stop: ## Stop Docker container
	@echo "Stopping Docker container..."
	@docker compose down

.PHONY: docker-logs
docker-logs: ## Show Docker container logs
	@docker compose logs -f

.PHONY: all
all: test build ## Run tests and build

.PHONY: ci
ci: test build ## CI pipeline simulation
	@echo "CI pipeline completed successfully"

# Install — copy configs to remote host
.PHONY: install
install: ## Copy .env and docker-compose.yml to remote host
	@echo "Installing $(APP_NAME) on $(HOST)..."
	-ssh root@$(HOST) "mkdir -p /opt/$(APP_NAME)"
	-ssh root@$(HOST) "touch /opt/$(APP_NAME)/blocked_ips.json"
	scp ./.env root@$(HOST):/opt/$(APP_NAME)/.env
	scp ./docker-compose.yml root@$(HOST):/opt/$(APP_NAME)/docker-compose.yml
	@echo "Install complete. Run 'make deploy' to start."

# Deploy — pull latest image and restart
.PHONY: deploy
deploy: ## Pull latest Docker image and restart service on remote host
	@echo "Deploying $(APP_NAME) to $(HOST)..."
	ssh root@$(HOST) "docker pull ghcr.io/mikhail-angelov/$(APP_NAME):latest"
	-ssh root@$(HOST) "cd /opt/$(APP_NAME) && docker compose down"
	ssh root@$(HOST) "cd /opt/$(APP_NAME) && docker compose up -d"
	@echo "Deploy complete."