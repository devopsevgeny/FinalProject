# Convenience targets for rebuilding ConfMgr locally.
#
# Usage examples:
#   make clean            # stop stack and remove volumes (fresh DB)
#   make build            # docker compose build (with cache)
#   make build-nocache    # docker compose build --no-cache
#   make up               # start stack in background
#   make fresh            # clean + build-nocache + up
#   make backend-build    # rebuild backend service only
#   make frontend-build   # rebuild frontend image only
#
# Note: these commands require local Docker access; they cannot run inside the
# Codex sandbox.

COMPOSE ?= docker compose

.PHONY: clean down build build-nocache backend-build backend-build-nocache frontend-build frontend-build-nocache up restart fresh

down:
	$(COMPOSE) down --remove-orphans

clean:
	$(COMPOSE) down --volumes --remove-orphans

build:
	$(COMPOSE) build

build-nocache:
	$(COMPOSE) build --no-cache

backend-build:
	$(COMPOSE) build backend

backend-build-nocache:
	$(COMPOSE) build --no-cache backend

frontend-build:
	$(COMPOSE) build frontend

frontend-build-nocache:
	$(COMPOSE) build --no-cache frontend

up:
	$(COMPOSE) up -d

restart: down up

fresh: clean build-nocache up
