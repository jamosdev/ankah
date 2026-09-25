COMPOSE ?= docker compose
COMPOSE_FILE := compose.yaml
PROMETHEUS_PORT ?= 9090
GRAFANA_PORT ?= 3000

export PROMETHEUS_PORT
export GRAFANA_PORT

.PHONY: up down reset logs ps test

up:
	$(COMPOSE) -f $(COMPOSE_FILE) up --build -d --wait

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down --remove-orphans

reset:
	$(COMPOSE) -f $(COMPOSE_FILE) down -v --remove-orphans

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

ps:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

test:
	python3 smoke.py
