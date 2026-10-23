SHELL := /bin/sh
COMPOSE ?= docker compose
TARGET ?= Vault.sol
MODE ?= mock
RUN_ARGS ?= --bounty -vvv

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs ps shell composer foundry-build foundry-test targets audit demo demo-all verify clean-runs

help: ## Show the demo commands
	@printf "ChainProof targets\n\n"
	@printf "  make up            build and start Anvil + PHP workbench (http://localhost:8000)\n"
	@printf "  make demo          audit Vault.sol, prove the reentrancy and pay the bounty\n"
	@printf "  make demo-all      run all three sandbox targets (proven, proven, rejected)\n"
	@printf "  make audit TARGET=Treasury.sol MODE=live RUN_ARGS=--bounty\n"
	@printf "  make foundry-test  forge test inside the container\n"
	@printf "  make verify        composer validate + lint + forge test\n"
	@printf "  make logs / down   follow logs / stop the stack\n"

build: ## Build the PHP + Foundry image
	$(COMPOSE) build

up: ## Start Anvil and the workbench
	$(COMPOSE) up -d --build
	@printf "workbench: http://localhost:8000\n"
	@printf "anvil:     http://localhost:8545 (chain id 31337)\n"

down: ## Stop the stack
	$(COMPOSE) down

restart: down up ## Recreate the stack

logs: ## Follow application logs
	$(COMPOSE) logs -f app

ps: ## Show container status
	$(COMPOSE) ps

shell: ## Open a shell in the app container
	$(COMPOSE) exec app bash

composer: ## Install PHP dependencies inside the container
	$(COMPOSE) exec app composer install --prefer-dist

foundry-build: ## Compile the Solidity targets
	$(COMPOSE) exec app forge build --root foundry

foundry-test: ## Run the hermetic Foundry self-checks
	$(COMPOSE) run --rm --no-deps app forge test --root foundry -vvv

targets: ## List sandbox targets
	$(COMPOSE) exec app php bin/console audit:targets

audit: ## Run one audit: make audit TARGET=Vault.sol MODE=mock
	$(COMPOSE) exec app php bin/console audit:run $(TARGET) --mode=$(MODE) $(RUN_ARGS)

demo: ## Run the flagship demo (Vault reentrancy + bounty)
	$(MAKE) audit TARGET=Vault.sol MODE=mock RUN_ARGS="--bounty -vvv"

demo-all: ## Run every sandbox target
	$(COMPOSE) exec app php bin/console audit:run Vault.sol --mode=mock --bounty -vvv
	$(COMPOSE) exec app php bin/console audit:run Treasury.sol --mode=mock --bounty -vvv
	$(COMPOSE) exec app php bin/console audit:run GuardedVault.sol --mode=mock --bounty -vvv

verify: ## Lint PHP/Twig/YAML, then run Foundry tests
	$(COMPOSE) exec app composer validate --no-check-publish
	$(COMPOSE) exec app php bin/console lint:yaml config
	$(COMPOSE) exec app php bin/console lint:twig templates
	$(COMPOSE) exec app php bin/console lint:container
	$(COMPOSE) run --rm --no-deps app forge test --root foundry -vvv

clean-runs: ## Remove local run artifacts (asks first)
	@printf "This deletes var/runs/*. Continue? [y/N] " && read answer && [ "$$answer" = "y" ]
	rm -rf var/runs/*
