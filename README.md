# Sherlock

**Agentic threat hunting on the ELK stack.** A plain-English hypothesis goes in; an
**evidenced verdict** comes out — and every claim in that verdict is tied to a
reproducible Elasticsearch query. The guiding rule is *no evidence, no claim*.

This is the **collaboration repo**: a clean, component-based architecture that five
people build in parallel. The complete, working **reference implementation** lives in
the sibling **`sherlock-demo/`** repo — read it to see what "done" looks like.

## Architecture

```
core/                     # the foundation every component depends on (owner: P1)
├─ contracts.py           #   shapes that cross a component boundary — the written interface
├─ settings.py  es.py     #   config + Elasticsearch client
├─ llm.py  providers.py   #   LLM client + multi-provider layer
├─ evidence_ledger.py     #   records every tool call so a finding can cite it
├─ reporter.py            #   renders the final evidenced report
├─ pipeline.py            #   wires a hunt: engine → verify → reduce → report
└─ mcp/                   #   MCP server + tool surface + client (the agent's ONLY interface)
components/               # five independently implementable slices — each imports ONLY core
├─ ingestion/             #   pull/push/stream + agentic auto-schema         (P2)
├─ normalization/         #   7-SIEM → canonical n_* fields                  (P3)
├─ detection/             #   Sigma-rule migration                          (P3)
├─ hunt/                  #   LLM agent loop + deterministic scanner         (P4)
└─ harness/               #   verifier + verdict reducer (anti-hallucination)(P5)
app/                      # CLI + web dashboard (owner: P1)
experiment/               # accuracy benchmark, repeatability, ablation      (P5)
datasets/                 # dataset onboarding (see Data below)
tests/                    # acceptance tests — the spec for each component
```

**Dependency rule:** components depend on `core`; `core` depends on no component. The
only inter-component edge is **ingestion → normalization** (normalization runs inside
the ingest pipeline). The graph is acyclic, so each slice is still built and tested
independently against the others' stable interfaces. See [`CONTRIBUTING.md`](CONTRIBUTING.md)
and [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md).

## Data

Sherlock runs on **public, authoritative attack telemetry** — the
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (a.k.a. Mordor,
MIT-licensed): real Windows/Sysmon/PowerShell event logs captured while a specific
MITRE ATT&CK technique was executed, so each dataset is its own ground-truth label.
`datasets/mordor_import.py` pulls them on demand through the normal ingestion pipeline;
see [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md) for every dataset, its ATT&CK id and
its exact source path.

## Run it

```bash
uv sync                       # set up the environment
make test                     # run the acceptance suite
make up                       # start Elasticsearch + Kibana (Docker)
uv run python -m datasets.mordor_import   # ingest the public datasets
make hunt H="Was a backdoor account created on this host?"
make dashboard                # web UI at http://localhost:8080
```

On a fresh checkout the acceptance tests show as **xfail** (the components are stubs);
each one turns into a real pass as its owner implements the slice.
