# Sherlock — Agentic Threat Hunting on the ELK Stack

**Plain-English hypothesis in → evidenced verdict out.** A user types a hypothesis in
natural language; agentic workflows plan the hunt, query an Elasticsearch SIEM **only
through an MCP tool surface**, gather evidence, and return an evidenced verdict where
**every claim is tied to the exact query that produced it** — and any claim that is not
is rejected by a verifier before it can reach the report. The guiding rule is
*no evidence, no claim*.

This is the **collaboration repo**: a clean, component-based architecture that five
people build in parallel. The complete, working **reference implementation** lives in
the sibling **`sherlock-demo/`** repo — read it to see what "done" looks like, and for
full run / data / configuration instructions.

---

## Architecture

```
core/                     # the foundation every component depends on (P1)
├─ contracts.py           #   shapes that cross a component boundary — the written interface
├─ settings.py  es.py     #   config + Elasticsearch client
├─ llm.py  providers.py   #   LLM client + multi-provider layer (13+ back-ends)
├─ evidence_ledger.py     #   records every tool call so a finding can cite it
├─ reporter.py            #   renders the final evidenced report
├─ pipeline.py            #   wires a hunt: engine → verify → reduce → report
└─ mcp/                   #   MCP server + query-tool surface + client (the agent's ONLY interface)
components/               # five independently implementable slices — each imports ONLY core
├─ ingestion/             #   pull/push/stream + agentic auto-schema         (P2)
├─ normalization/         #   7-SIEM → canonical n_* fields                  (P3)
├─ detection/             #   Sigma-rule migration                          (P3)
├─ hunt/                  #   LLM agent loop + deterministic scanner         (P4)
└─ harness/               #   verifier + verdict reducer (anti-hallucination)(P5)
app/                      # CLI + web dashboard                              (P1)
experiment/               # accuracy benchmark, repeatability, ablation      (P5)
datasets/                 # public-dataset onboarding (OTRF Security-Datasets)
tests/                    # acceptance tests — the written spec for each component
```

**How a hunt flows.** A hypothesis enters the **hunt engine** (LLM agent *or*
deterministic scanner); the engine may touch the data **only** through the **MCP
query tools** (`count_logs` / `search_logs` / `aggregate` …), and every call is written
to the **evidence ledger**. The **verifier** then drops any finding whose cited query
did not exist / did not run / matched in the wrong direction, and the **reducer**
re-derives the verdict from what survives — never from the model's own word. The
**reporter** shows the verdict, every finding's query, and every rejected claim.

**Dependency rule.** Each `components/<x>/` package imports from `core` only; `core`
imports no component. The single documented exception is **ingestion → normalization**
(normalization runs inside the ingest pipeline). The graph is acyclic, so each slice is
built and tested independently against the others' stable interfaces — which is what
lets five people work in parallel. See [`CONTRIBUTING.md`](CONTRIBUTING.md),
[`docs/OWNERSHIP.md`](docs/OWNERSHIP.md) and [`docs/CONTRACTS.md`](docs/CONTRACTS.md).

---

## Division of labour

Five slices, one owner each; everyone owns a code area **+** a report section **+** a
block of the pitch deck. §1 (Executive Summary) and §7 (Conclusion) are written
together. **Owners are not assigned yet** — fill the column once the team decides.
Details: [`docs/DIVISION.md`](docs/DIVISION.md), [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md).

| Part | Owner | Code area | Report section | Pitch (14-page deck) |
|---|---|---|---|---|
| **P1 — Platform & orchestration** | ____ | `core/` (incl. MCP query-tool surface), `app/`, `docker/`, CI | §2 Architecture & reproducible setup | Part 1 — Cover · Problem |
| **P2 — Ingestion** | ____ | `components/ingestion/` | §3 Ingestion & agentic auto-schema | Part 2 — The rule · How it works |
| **P3 — Interoperability** | ____ | `components/normalization/`, `components/detection/` | §4 Normalise-first & Sigma | Part 3 — Key strengths |
| **P4 — Hunt engine** | ____ | `components/hunt/` | §5 Agentic workflow design | Part 4 — Proof |
| **P5 — Guardrails & evaluation** | ____ | `components/harness/`, `experiment/` | §6 Guardrails & experiment results | Part 5 — Why this approach · Conclusion · Team |

---

## Run it

Full instructions, LLM-provider setup and the public dataset download are in the
**`sherlock-demo/`** README. In short:

```bash
uv sync                                     # set up the environment
make test                                   # acceptance suite (stubs show as xfail)
make up                                     # start Elasticsearch + Kibana (Docker)
uv run python -m datasets.mordor_import     # ingest the public OTRF datasets
make hunt H="Was a backdoor account created on this host?"
make dashboard                              # web UI at http://localhost:8080
```

Data provenance (every dataset + its ATT&CK id): [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md).
The project report is in [`docs/REPORT.md`](docs/REPORT.md).
