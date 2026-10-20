# Sherlock — one-command operations. Requires Docker + uv.
H ?= An external actor brute-forced the administrator account and gained access

.PHONY: help up down wipe install seed siem scenario hunt experiment dashboard mcp status schemas providers pull-watch stream-demo demo

help:
	@echo "make up         - start Elasticsearch + Kibana (Docker)"
	@echo "make install    - create the Python venv (uv sync)"
	@echo "make seed       - generate + agentically ingest 3 log types"
	@echo "make siem       - onboard the incident in 7 SIEM schemas (CEF/LEEF/CIM/ECS/OCSF/ASIM/UDM)"
	@echo "make scenario   - load extra test scenarios (benign / password-spray / data-exfil)"
	@echo "make dashboard  - run the web dashboard (http://localhost:8080)"
	@echo "make hunt H='..'- run a hunt from the CLI"
	@echo "make experiment H='..' - run the same hunt twice and diff"
	@echo "make demo       - up + install + seed + dashboard (full local bring-up)"
	@echo "make status     - cluster/index overview"
	@echo "make down       - stop containers   |   make wipe - stop + delete data"

up:
	docker compose up -d --build
	@echo "waiting for Elasticsearch…"
	@until curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; do sleep 3; done
	@echo "Elasticsearch is up on :9200 (Kibana on :5601, may take ~1 min more)"

down:
	docker compose down

wipe:
	docker compose down -v

install:
	uv sync

seed: install
	uv run python -m app.cli seed $(if $(LLM),,--no-llm)

siem: install
	uv run python -m app.cli siem $(if $(LLM),,--no-llm)

scenario: install
	uv run python -m app.cli scenario $(NAME)

sigma: install
	uv run python -m app.cli sigma $(if $(LLM),--llm,) $(FILES)

hunt: install
	uv run python -m app.cli hunt "$(H)"

experiment: install
	uv run python -m app.cli experiment "$(H)" $(if $(LLM),,--no-llm)

dashboard: install
	uv run python -m app.cli dashboard

providers: install
	uv run python -m app.cli providers

mcp: install
	uv run python -m app.cli mcp

status:
	uv run python -m app.cli status

schemas:
	uv run python -m app.cli schemas

pull-watch: install
	uv run python -m ingestion.pull

stream-demo: install
	uv run python -m ingestion.stream --send datasets/generated/web_access.log

demo: up install seed
	@echo "\n>>> Bring-up complete. Starting dashboard on http://localhost:8080\n"
	uv run python -m app.cli dashboard
