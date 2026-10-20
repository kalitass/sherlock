# SE6014 Project Report — Sherlock

**Option chosen: Q1 — Agentic Threat Hunting on the ELK Stack.**

> **Group [N]**
>
> | Member | Matriculation no. |
> |---|---|
> | [Member 1] | [G…] |
> | [Member 2] | [G…] |
> | [Member 3] | [G…] |
> | [Member 4] | [G…] |
> | [Member 5] | [G…] |
>
> Code repository: **[repo URL]** · Submitted: [date]

---

## Table of Contents
1. Executive Summary (non-technical)
2. System Architecture
3. Reproducible Setup & Challenges
4. Agentic Workflow Design — Completeness, Accuracy & Guardrails
5. Experiment Results
6. Conclusion — Limitations & Next Steps
7. Appendix A — Division of Labour & Timesheet

---

## 1. Executive Summary (non-technical)

Security teams are drowning in logs. A modern estate emits millions of events a day,
and hunting for an intrusion means an analyst hand-writing queries, one hypothesis at
a time. The obvious fix — point an AI at the logs — fails the first trust test:
language models confidently make things up, and in security a fabricated "intrusion"
wastes a day while a missed one is a breach.

**Sherlock** is an AI threat-hunting assistant built around one rule: *no evidence, no
claim*. You give it a hypothesis in plain English ("was a backdoor account created on
this host?"); it plans an investigation, queries an Elasticsearch SIEM through a
controlled tool interface, and returns a **verdict in which every statement is tied to
a reproducible query**. A guardrail re-computes the verdict from only the evidence that
actually checks out, so an analyst can audit any conclusion back to the data.

**What we proved.** On a public, independently-labelled corpus of real attack telemetry
(the OTRF Security-Datasets), Sherlock reached a **verdict on 20 ground-truth hypotheses
spanning 14 MITRE ATT&CK techniques across 7 tactics with 100% accuracy and a 0%
false-positive rate**, gave the **same verdict on repeated runs**, and its guardrail
**caught 6% of the model's own claims as unsupported** before they reached the report.

**What it still cannot do.** It does not invent coverage it does not have: the breadth
of techniques and time windows a hunt considers is driven by the language model's
judgement, not a provable guarantee, and the deterministic scanner only knows the
patterns we encoded. Sherlock makes automation *trustworthy and auditable*; it does not
replace an analyst's judgement on what to ask.

---

## 2. System Architecture

Sherlock is organised as a shared **`core`** foundation plus five independently-owned
components. The agent can touch the data **only** through the MCP tool surface, and
every tool call is recorded, so nothing reaches a verdict unaudited.

```
                 plain-English hypothesis
                          │
                   ┌──────▼───────┐        ┌──────────────────────────┐
                   │  hunt engine │ tools  │  core/mcp  (MCP server)   │
                   │  (LLM agent  ├───────▶│  count_logs/search_logs/  │
                   │   or scanner)│        │  aggregate + context tools│──▶ Elasticsearch
                   └──────┬───────┘        └──────────────────────────┘      (ELK)
          findings (each  │   every call recorded ▼
          citing evidence)│        ┌───────────────────────────┐
                          └───────▶│ evidence ledger           │
                                   └─────────────┬─────────────┘
                                                 ▼
                        ┌────────────────────────────────────────┐
                        │ harness: verifier → reducer            │
                        │  drop any claim whose cited query does │
                        │  not exist / didn't run / wrong        │
                        │  direction; re-derive the verdict from │
                        │  what survives (never the model's word)│
                        └────────────────────┬───────────────────┘
                                             ▼
                          evidenced report (verdict + every query)
```

**Components (and owners).**

- **`core/` — platform & orchestration (P1).** Cross-component contracts
  (`core/contracts.py`), settings, the Elasticsearch client, the LLM/provider client,
  the evidence ledger, the MCP server + tool surface + client, and the hunt pipeline
  that wires engine → verify → reduce → report. `app/` holds the CLI and dashboard.
- **`components/ingestion/` — ingestion & auto-schema (P2).** Three ingestion modes
  (pull / push / stream) and an agentic auto-schema step: a new source is fingerprinted,
  a parser is proposed and validated on a sample, then registered for reuse — no code
  change, no restart.
- **`components/normalization/` — SIEM normalization (P3).** Maps any of seven SIEM
  schemas (CEF, LEEF, CIM, ECS, OCSF, ASIM, UDM) onto one canonical `n_*` field set, so
  a single detection or query is portable across formats ("normalise first").
- **`components/detection/` — Sigma migration (P3).** Imports existing SigmaHQ YAML
  rules, maps their fields to `n_*`, and translates them into one MCP query.
- **`components/hunt/` — hunt engines (P4).** The LLM agent loop (plan → query → cite),
  and a deterministic scanner that sweeps the corpus for known ATT&CK patterns.
- **`components/harness/` — guardrails (P5).** The verifier (citation integrity) and the
  reducer (verdict re-derived from verified, hypothesis-addressing evidence).

**Boundary rule.** A component imports only from `core`; `core` imports no component.
This keeps the five slices independently buildable and testable.

The agent is **model-agnostic**: a provider layer runs 13+ LLM back-ends behind one
interface, so the same pipeline runs on a cloud model (DeepSeek in our experiments) or a
local model with no code change.

---

## 3. Reproducible Setup & Challenges

**Bring-up** (requires Docker + [uv](https://docs.astral.sh/uv/)):

```bash
make up                     # start Elasticsearch + Kibana (docker compose)
make mordor                 # download + agentically ingest the public OTRF datasets
make hunt H="Was a backdoor account created on this host?"
make dashboard              # web UI at http://localhost:8080
make test                   # the component acceptance suite
```

Everything is environment-driven (`.env`), so a run is reproducible from a single
config. The code repository is at **[repo URL]**; the complete reference implementation
is in the `sherlock-demo` repo and the collaboration scaffold (one component per member)
in `sherlock`.

**Data.** Sherlock uses **only public, third-party-labelled** telemetry — the
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT). Each dataset
is real Windows/Sysmon/PowerShell event data captured while a specific ATT&CK technique
was executed, which is what lets us treat the technique as ground truth. Provenance and
the full per-dataset table are in `docs/DATA_SOURCES.md`. `datasets/mordor_import.py`
pulls them on demand through the normal ingestion pipeline, so onboarding them is itself
a demonstration of the agentic auto-schema step on data the system has never seen.

**Challenges we hit.**
- *Schema-on-write vs. schema-on-read.* We normalise at ingest (schema-on-write) onto
  `n_*`, trading ingest cost for fast, portable queries and stable detections.
- *One event, seven spellings.* The same logon looks different in all seven SIEM
  schemas; the normalization layer and its unit test (`test_normalise_all_seven_agree`)
  pin that they collapse to one canonical shape.
- *Trusting a non-deterministic agent.* An LLM takes a different investigation path each
  run. We made the **verdict**, not the narrative, the stable output (Section 4).

---

## 4. Agentic Workflow Design — Completeness, Accuracy & Guardrails

A hunt runs **hypothesis → plan → query (via MCP) → verify → report**. The design goal
is *trustworthy* automation: a claim only ships if it is tied to evidence.

**Coverage (completeness).** We are deliberate about what we can and cannot quantify:
- **Data sources — quantified.** The evidence ledger records which indices every query
  touched; coverage is reported as `sources_searched` vs. `sources_available` and is
  *fail-closed* (an unknown source list or a failed query is never counted as complete).
- **Techniques — enumerable, not exhaustive.** The benchmark exercises 14 named ATT&CK
  techniques across 7 tactics; the LLM is prompted to think in techniques (brute force,
  valid-account abuse, web shells, encoded PowerShell, persistence, log clearing, C2).
  We do **not** claim a technique-coverage percentage — the technique space is unbounded.
- **Time — full window.** The deterministic scanner never time-filters (it sees the
  whole window); the LLM is prompted to consider the full range. We treat time coverage
  as guided, not provably bounded — an honest limitation.

**Evidence binding (accuracy).** Every finding cites the `evidence_id`s of the tool
calls behind it. The **verifier** keeps a finding only if *every* cited id (a) exists in
this hunt's ledger, (b) came from a query tool (`count_logs`/`search_logs`/`aggregate`),
(c) ran successfully, and (d) matched in the claim's direction (a presence claim must
cite a ≥1-hit query; an absence claim a 0-hit query). The **reducer** then re-derives the
verdict from the surviving, hypothesis-addressing findings — using an enumerable
`supports_hypothesis` field the model emits (does this finding argue the hypothesis is
true?), never the model's self-reported verdict.

**Hallucination — prevented and detected.** Prevention: the agent can only act through
the bounded MCP tools, the system prompt makes evidence citation mandatory, and tool
output is treated strictly as untrusted data (never as instructions). Detection: the
verifier quarantines every unsupported claim into a visible "rejected" section — so a
fabricated or mis-cited claim cannot reach the verdict. A **confirmed** verdict is
structurally impossible without a real query that returned supporting data.

**Guardrails / safety.** Tools are scoped to `sherlock-logs-*` with size, interval and
query-length bounds; a hunt can be confined to one source with `SHERLOCK_LOG_SCOPE`; a
provider/network failure degrades to the deterministic engine instead of crashing; and
the final report is schema-validated and output-escaped.

---

## 5. Experiment Results

All numbers below are from logged runs on the public OTRF corpus (~36,700 real events,
14 techniques / 7 tactics), engine DeepSeek at temperature 0. Raw result files:
`docs/benchmark_results_deepseek.md`, `docs/experiment_results.md`,
`docs/naive_baseline_results.md`, and `experiment/*.json`.

### 5.1 Detection accuracy (20 labelled hypotheses)

14 hypotheses name a technique a capture actually contains (should **confirm**); 6 name
a technique absent from a capture (should **not**).

| Metric | Value |
|---|---|
| Attacks detected (recall) | **14 / 14 (100%)** |
| False-positive rate | **0%** |
| Precision · F1 | **100% · 100%** |
| Overall accuracy (20 cases) | **100%** |

Confusion matrix: TP 14 · FN 0 · FP 0 · TN 6. Every real attack caught; zero false alarms.

### 5.2 Anti-hallucination (claim integrity)

| | Value |
|---|---|
| Claims the LLM asserted (all hunts) | **123** |
| Claims the harness rejected as unsupported | **7 (6%)** |
| Raw claim integrity (trust the LLM) | **~94%** |
| Harness claim integrity (by construction) | **100%** |

The rejected claims cluster on the *no-attack* hypotheses — i.e. the model over-claiming
when there is nothing to find, which is exactly where a guardrail earns its keep.

### 5.3 Repeatability (same hypothesis, run twice)

Four hypotheses were each run twice, back-to-back, with the dataset hashed before and
after to prove the input did not change.

| | Value |
|---|---|
| Verified-verdict agreement | **4 / 4** |
| Mean verified-finding overlap (Jaccard) | **0.55** |
| Mean query-plan overlap (Jaccard) | **0.12** |

The agent takes a *markedly different investigation path* each run (query-plan overlap
is only ~0.12), yet reaches the *same verdict every time* (4/4) — because the verdict is
derived from verified evidence, not the model's wording. Convergence is engineered via (1) temperature 0,
(2) a coverage-first system contract, (3) a forced final answer on budget exhaustion, and
(4) the evidence gate.

### 5.4 The guardrail's value (ablation)

Removing the harness entirely (same strong model, neutral prompt, verdict taken at face
value) left verdict accuracy unchanged at **100%** — the guardrail adds verifiability at
**zero accuracy cost**. Its measurable contribution is at the *claim* level (§5.2: 6% of
claims caught) and as a *safety property*: a weaker local model, run through the same
pipeline, missed most attacks (low recall) but **still never raised a false alarm**,
because a confirmed verdict cannot be produced without a verified query. Capability
drives recall; the harness drives trust.

### 5.5 Deterministic scanner (public corpus sweep)

The no-LLM scanner, re-pointed to the OTRF corpus, swept all indices and detected
**15 / 15** probed ATT&CK techniques deterministically — a repeatable, audit-grade
detection pass that complements the adaptive LLM engine.

---

## 6. Conclusion — Limitations & Next Steps

Sherlock shows that an agentic hunter can be made *trustworthy*: on real, labelled attack
telemetry it is accurate (100% / 0% FPR), reproducible, and every conclusion is tied to a
query an analyst can re-run — with a guardrail that catches the model's unsupported claims.

**Limitations.** Technique and time-window coverage are driven by the LLM's judgement, not
a provable guarantee; the deterministic scanner only detects patterns we encoded; and the
benchmark, while real and third-party-labelled, is a focused subset of the attack space.

**Next steps.** Broaden the benchmark toward the full OTRF library (150+ captures, incl.
multi-stage APT datasets); add cost/latency reporting per hunt; and explore a
coverage-planning step that makes the technique set a hunt considers explicit and
reviewable.

---

## 7. Appendix A — Division of Labour & Timesheet

Balance is across **code + report + demo**, not lines alone. Full per-module ownership and
the acceptance-test mapping are in `docs/OWNERSHIP.md`.

| Member | Component(s) owned | Report section | Demo / pitch part | Hours |
|---|---|---|---|---|
| [Member 1] — P1 | `core/`, `app/`, CI | §2 Architecture, §3 Setup | Stack bring-up + MCP surface | [~__] |
| [Member 2] — P2 | `components/ingestion/` | §3 (ingestion) | Auto-schema onboarding | [~__] |
| [Member 3] — P3 | `components/normalization/`, `components/detection/` | §4 (interoperability) | 7-SIEM + Sigma | [~__] |
| [Member 4] — P4 | `components/hunt/` | §4 (workflow) | Live hunt | [~__] |
| [Member 5] — P5 | `components/harness/`, `experiment/` | §4 (guardrails), §5 Experiments | Evidence gate + numbers | [~__] |

_Timesheet: fill each member's hours (coding + report + rehearsal). Suggested order of
magnitude ~25–35 h each._
