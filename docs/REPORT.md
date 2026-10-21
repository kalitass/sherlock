# SE6014 Project Report — Sherlock

**Option chosen: Q1 — Agentic Threat Hunting on the ELK Stack.**

> **Group [N]**
>
> | Member | Matriculation no. |
> |---|---|
> | Bian Tianyue | [G…] |
> | Gao Bin | [G…] |
> | Ma Yuzhe | [G…] |
> | Qin Ziyou | [G…] |
> | Xu Zilong | [G…] |
>
> Code repository: **[repo URL]** · Submitted: [date]

---

## Table of Contents

**Shared:** §1 Executive Summary (non-technical) · §7 Conclusion (Limitations & Next Steps) · Appendix A (Division of Labour & Timesheet)

**One section per member — edit only your own:**

- §2 · System Architecture & Reproducible Setup — **P1**
- §3 · Ingestion & Agentic Auto-schema — **P2**
- §4 · Interoperability — Normalise-first & Sigma — **P3**
- §5 · Agentic Workflow Design — **P4**
- §6 · Guardrails & Experiment Results — **P5**

> **How to edit this report.** Sections 2–6 are one-per-member: edit *only* your own
> section. Section 1 (lead: P1) and Section 7 are written together; whoever changes a
> shared number tells the group. Keep each section self-contained so there are no merge
> collisions. Fill the cover table and the Appendix timesheet before submission.

---

## 1. Executive Summary (non-technical)   *(shared — lead: P1)*

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

## 2. System Architecture & Reproducible Setup   *(owner: P1 — [Member 1])*

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
- **`components/ingestion/` — ingestion & auto-schema (P2).** See §3.
- **`components/normalization/` + `components/detection/` — interoperability (P3).** See §4.
- **`components/hunt/` — hunt engines (P4).** See §5.
- **`components/harness/` — guardrails (P5).** See §6.

**Boundary rule.** A component imports only from `core`; `core` imports no component.
The one documented exception is `ingestion → normalization` (normalization runs inside
the ingest pipeline). The graph is acyclic, which keeps the five slices independently
buildable and testable — this is what lets five people work in parallel without merge
collisions.

The agent is **model-agnostic**: a provider layer runs 13+ LLM back-ends behind one
interface, so the same pipeline runs on a cloud model (DeepSeek in our experiments) or a
local model with no code change.

**Bring-up** (requires Docker + [uv](https://docs.astral.sh/uv/)):

```bash
make up                     # start Elasticsearch + Kibana (docker compose)
make mordor                 # download + agentically ingest the public OTRF datasets
make hunt H="Was a backdoor account created on this host?"
make dashboard              # web UI at http://localhost:8080
make test                   # the component acceptance suite
```

Everything is environment-driven (`.env`): copy `.env.example`, set `SHERLOCK_LLM_PROVIDER`
and the matching `*_API_KEY`, and a run is reproducible from a single config. (The
deterministic scanner needs no key.) The complete reference implementation is in the
`sherlock-demo` repo; the collaboration scaffold — one component per member — is in
`sherlock`.

**Challenges we hit.**
- *Schema-on-write vs. schema-on-read.* We normalise at ingest (schema-on-write) onto
  `n_*`, trading ingest cost for fast, portable queries and stable detections.
- *Trusting a non-deterministic agent.* An LLM takes a different investigation path each
  run; we made the **verdict**, not the narrative, the stable, audited output (§5–§6).
- *Apple-Silicon ELK.* We build a patched Elasticsearch image (`docker/es`) so the stack
  comes up reproducibly on M-series Macs.

---

## 3. Ingestion & Agentic Auto-schema   *(owner: P2 — [Member 2])*

**The requirement.** Onboard a new log source by *pointing* at it — no hand-written
parser, no restart — and support the three ingestion modes.

**Three ingestion modes.**
- **Pull** — drop a file into a watched directory; it is picked up, auto-schema'd and indexed.
- **Push** — an endpoint agent `POST`s a JSON batch to `/api/ingest/push` (size-bounded).
- **Stream** — a continuous syslog/UDP feed is consumed and flushed in batches.

**Agentic auto-schema (the core of this slice).** For every new source the pipeline:
1. **Fingerprints** a sample — a structural signature of the record shape.
2. **Reuses** a registered schema if the fingerprint already matches (idempotent onboarding).
3. Otherwise **proposes a parser** — LLM-assisted when a key is available, with a
   deterministic heuristic proposer as the always-available fallback — then **validates**
   it against a sample and only **registers** it if the parse rate clears a threshold
   (otherwise the schema is *quarantined*, not silently trusted).
Each source lands in its own index `sherlock-logs-<type>`; the schema (field map,
validation rate, `created_by`) is persisted to the `sherlock-schemas` registry and shown
on the dashboard's **Sources & schemas** page.

**Idempotent ingestion.** Each document's `_id` is a content hash (SHA-1 of the
normalised doc), so replaying a file or re-running ingest never duplicates events — which
also makes the whole demo reproducible.

**Demonstrated on data the system has never seen.** Onboarding the 14 public OTRF
datasets runs exactly this path: `datasets/mordor_import.py` pulls each capture and calls
the normal `ingest_records` auto-schema step (raw PascalCase Windows/Sysmon fields
preserved; the agent adapts downstream via the field map). So "load the benchmark" *is* a
live demonstration of agentic ingestion.

**Schema-drift detection** (Week 2, *"drift breaks detections silently"*). Every ingest
runs an observed-vs-expected contract check; rename or drop a field a detection relies on
and the ingest surfaces `drift` (missing / added / type-changed fields) instead of quietly
matching nothing. Contracts live in `sherlock-schema-contracts`; an intentional change is
re-accepted with `schema_drift.rebaseline()`.

---

## 4. Interoperability — Normalise-first & Sigma   *(owner: P3 — [Member 3])*

**The problem.** *A detection is only as portable as its schema.* The same logon event
is spelled differently in each of the seven SIEM schemas the course teaches, so a query
written against one is useless against another.

**Normalise first.** At ingest, every event is mapped onto one canonical `n_*` field set
(`n_user`, `n_src_ip`, `n_event_id`, `n_action`, …) using the lecture's field-mapping
tables, so **one query or detection fires identically across all seven formats**:

| Schema | Vendor | Parsed by |
|---|---|---|
| **CEF** | ArcSight | deterministic wire-format parser |
| **LEEF** | IBM QRadar | deterministic wire-format parser |
| **CIM** | Splunk | JSON introspection |
| **ECS** | Elastic | JSON introspection |
| **OCSF** | (open standard) | JSON introspection |
| **ASIM** | MS Sentinel | JSON introspection |
| **UDM** | Google SecOps | JSON introspection |

```bash
# the SAME canonical query matches the identical event rendered in all seven schemas
n_event_id=4625 AND n_user=administrator AND n_src_ip=203.0.113.66 AND n_action=failure
```

The agreement is pinned by the unit test `test_normalise_all_seven_agree`: the same event
rendered in all seven schemas collapses to one canonical shape — proven without needing a
key or an ingested synthetic dataset. Normalization runs *inside* the ingest pipeline (the
one documented inter-component edge, §2).

**Sigma migration.** To reuse the community's detection corpus rather than rewrite it,
`components/detection/sigma_import.py` imports existing SigmaHQ YAML rules, maps their
`logsource`/fields onto `n_*`, and translates each into a single MCP query — so a public
Sigma rule becomes an executable Sherlock detection against normalised data.

**Why it matters.** Normalise-first + Sigma import is what lets the *same* hunt logic run
over heterogeneous sources, and lets Sherlock stand on existing detection content instead
of reinventing it.

---

## 5. Agentic Workflow Design   *(owner: P4 — [Member 4])*

A hunt runs **hypothesis → plan → query (via MCP) → verify → report**. The design goal is
*trustworthy* automation: a claim only ships if it is tied to evidence. Two engines share
the pipeline — an **LLM agent** (adaptive, interprets free-text hypotheses) and a
**deterministic scanner** (fixed ATT&CK probes, identical every run).

**The agent loop.** The LLM may act *only* through the bounded MCP tools
(`count_logs` / `search_logs` / `aggregate` + context tools). It plans an investigation,
issues queries, and must attach the `evidence_id`s of the tool calls behind every finding;
tool output is treated strictly as untrusted *data*, never as instructions.

**Coverage (completeness) — honest about what we can quantify.**
- **Data sources — quantified.** The evidence ledger records which indices every query
  touched; coverage is reported as `sources_searched` vs. `sources_available` and is
  *fail-closed* (an unknown source list or a failed query is never counted as complete).
- **Techniques — enumerable, not exhaustive.** The benchmark exercises 14 named ATT&CK
  techniques across 7 tactics; the LLM is prompted to think in techniques. We do **not**
  claim a technique-coverage percentage — the technique space is unbounded.
- **Time — full window.** The scanner never time-filters; the LLM is prompted to consider
  the full range. We treat time coverage as guided, not provably bounded — an honest limit.

**Scoping & resilience.** Tools are scoped to `sherlock-logs-*` with size, interval and
query-length bounds; a hunt can be confined to one source with `SHERLOCK_LOG_SCOPE`; and a
provider/network failure degrades to the deterministic engine instead of crashing.

**Deterministic scanner.** With no hypothesis, a battery of fixed ATT&CK probes sweeps the
whole corpus and reports detection posture — a repeatable, audit-grade pass that
complements the adaptive LLM engine (results in §6.5).

---

## 6. Guardrails & Experiment Results   *(owner: P5 — [Member 5])*

### 6.1 The guardrail (how "no evidence, no claim" is enforced)

Every finding cites the `evidence_id`s behind it. The **verifier** keeps a finding only if
*every* cited id (a) exists in this hunt's ledger, (b) came from a query tool, (c) ran
successfully, and (d) matched in the claim's direction (a presence claim must cite a
≥1-hit query; an absence claim a 0-hit query). The **reducer** then re-derives the verdict
from the surviving, hypothesis-addressing findings — using an enumerable
`supports_hypothesis` field the model emits (does this finding argue the hypothesis is
true?), never the model's self-reported verdict. Every unsupported claim is quarantined
into a visible "rejected" section, so a **confirmed** verdict is structurally impossible
without a real query that returned supporting data.

All numbers below are from logged runs on the public OTRF corpus (~36,700 real events,
14 techniques / 7 tactics), engine DeepSeek at temperature 0. Raw files:
`docs/benchmark_results_deepseek.md`, `docs/experiment_results.md`,
`docs/naive_baseline_results.md`, `experiment/*.json`.

### 6.2 Detection accuracy (20 labelled hypotheses)

14 hypotheses name a technique a capture actually contains (should **confirm**); 6 name a
technique absent from a capture (should **not**).

| Metric | Value |
|---|---|
| Attacks detected (recall) | **14 / 14 (100%)** |
| False-positive rate | **0%** |
| Precision · F1 | **100% · 100%** |
| Overall accuracy (20 cases) | **100%** |

Confusion matrix: TP 14 · FN 0 · FP 0 · TN 6. Every real attack caught; zero false alarms.

### 6.3 Anti-hallucination (claim integrity)

| | Value |
|---|---|
| Claims the LLM asserted (all hunts) | **123** |
| Claims the harness rejected as unsupported | **7 (6%)** |
| Raw claim integrity (trust the LLM) | **~94%** |
| Harness claim integrity (by construction) | **100%** |

The rejected claims cluster on the *no-attack* hypotheses — the model over-claiming when
there is nothing to find, which is exactly where a guardrail earns its keep.

### 6.4 Repeatability (same hypothesis, run twice)

Four hypotheses were each run twice, back-to-back, with the dataset hashed before and
after to prove the input did not change.

| | Value |
|---|---|
| Verified-verdict agreement | **4 / 4** |
| Mean verified-finding overlap (Jaccard) | **0.55** |
| Mean query-plan overlap (Jaccard) | **0.12** |

The agent takes a *markedly different investigation path* each run (query-plan overlap
~0.12), yet reaches the *same verdict every time* (4/4) — because the verdict is derived
from verified evidence, not the model's wording. Convergence is engineered via (1)
temperature 0, (2) a coverage-first system contract, (3) a forced final answer on budget
exhaustion, and (4) the evidence gate.

### 6.5 The guardrail's value (ablation) + deterministic scanner

Removing the harness entirely (same strong model, neutral prompt, verdict at face value)
left verdict accuracy unchanged at **100%** — the guardrail adds verifiability at **zero
accuracy cost**. Its measurable contribution is at the *claim* level (§6.3: 6% caught) and
as a *safety property*: a weaker local model, run through the same pipeline, missed most
attacks (low recall) but **still never raised a false alarm**, because a confirmed verdict
cannot be produced without a verified query. *Capability drives recall; the harness drives
trust.* Separately, the no-LLM scanner swept all indices and detected **15 / 15** probed
ATT&CK techniques deterministically — a repeatable, audit-grade pass.

---

## 7. Conclusion — Limitations & Next Steps   *(shared)*

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

## Appendix A — Division of Labour & Timesheet

Balance is across **code + report + demo**, not lines alone. Full per-module ownership and
the acceptance-test mapping are in `docs/OWNERSHIP.md`. Each member owns exactly one report
section (§2–§6).

Team: Bian Tianyue · Gao Bin · Ma Yuzhe · Qin Ziyou · Xu Zilong. **Fill the "Owner"
column once the team decides who takes which part** — this table only describes the five
parts; it does not pre-assign them.

| Owner | Component(s) | Report section | Demo / pitch part | Hours |
|---|---|---|---|---|
| ____ | `core/`, `app/`, CI | §2 Architecture & Setup | Stack bring-up + MCP surface | [~__] |
| ____ | `components/ingestion/` | §3 Ingestion & auto-schema | Auto-schema onboarding | [~__] |
| ____ | `components/normalization/`, `components/detection/` | §4 Interoperability | 7-SIEM + Sigma | [~__] |
| ____ | `components/hunt/` | §5 Workflow design | Live hunt | [~__] |
| ____ | `components/harness/`, `experiment/` | §6 Guardrails + experiments | Evidence gate + numbers | [~__] |

_Timesheet: fill each member's hours (coding + report + rehearsal). Suggested order of
magnitude ~25–35 h each._
