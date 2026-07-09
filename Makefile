# Shamir Secret Sharing — common developer tasks.
# Run `make` or `make help` to list targets.

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
COVERPROFILE  ?= coverage.out

.DEFAULT_GOAL := help
.PHONY: help all check build fmt vet lint test cover vuln clean

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

all: build vet lint test vuln ## Build, vet, lint, test, and scan for vulnerabilities

check: all ## Alias for `all`

build: ## Compile all packages
	$(GO) build ./...

fmt: ## Format all Go source
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run ./...

test: ## Run tests with the race detector
	$(GO) test -race ./...

cover: ## Run tests with coverage and open the HTML report
	$(GO) test -coverprofile=$(COVERPROFILE) ./...
	$(GO) tool cover -html=$(COVERPROFILE)

vuln: ## Scan for known vulnerabilities (govulncheck)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

clean: ## Remove generated files
	rm -f $(COVERPROFILE)
	$(GO) clean
