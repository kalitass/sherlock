# Division of labour — template (Group [__])

**Team:** Bian Tianyue · Gao Bin · Ma Yuzhe · Qin Ziyou · Xu Zilong

The work splits into **five parts**. Each part is one code area + one report section
+ a continuous block of the pitch. **The team has NOT assigned these yet** — this file
only describes the five parts; fill the "Owner" column once you decide. One person per part.

## The five parts

| Part | Owner | Code area | Report section | Pitch slides (14-page deck) |
|---|---|---|---|---|
| **P1 — Platform & setup** | ____ | `core/` (pipeline, es, settings, **MCP query-tool surface**), `app/`, `docker/`, README | §2 Architecture & Reproducible Setup | 1 Cover · 3 Problem (divider 2) |
| **P2 — Ingestion** | ____ | `components/ingestion/` (pull/push/stream, auto-schema) | §3 Ingestion & Agentic Auto-schema | 5 Rule · 6 How (divider 4) |
| **P3 — Interoperability (normalise-first + Sigma)** | ____ | `components/normalization/`, `components/detection/` (Sigma) | §4 Interoperability — Normalise-first & Sigma | 8 Key strengths (divider 7) |
| **P4 — Hunt engine (how the agent queries)** | ____ | `components/hunt/` (planner, executor, evidence ledger) | §5 Agentic Workflow Design | 10 Proof (divider 9) |
| **P5 — Guardrails & experiments** | ____ | `components/harness/` (verifier, reducer), `experiment/` | §6 Guardrails & Experiment Results | 12 Why this approach · 13 Conclusion · 14 Team (divider 11) |

(§1 Executive Summary and §7 Conclusion are written together; P1 leads.)

## What each part covers (plain words)

**Report sections**
- **§2 Architecture & Setup** — how the whole system is built, and how to run it in one go.
- **§3 Ingestion & auto-schema** — how logs get in (pull / push / stream); it figures out each format by itself.
- **§4 Interoperability** — **make 7 SIEM formats look the same** (CEF/LEEF/CIM/ECS/OCSF/ASIM/UDM →
  one `n_*` field set) so a single query fires across all of them, and **migrate existing Sigma rules**
  onto that field set. (The MCP query tools themselves live in `core/` — P1's foundation; §5 is how the
  agent *uses* them.)
- **§5 Workflow design** — how the AI agent **uses** those tools: plan → run queries → record every piece of evidence.
- **§6 Guardrails & experiments** — the evidence check that drops unsupported claims (verifier + reducer),
  plus all the test numbers (accuracy, false-positive rate, run-twice reproducibility).

**Pitch slides** (grouped so one person speaks a continuous block; each Part has its own "PART N" divider slide)
- **P1 — 1 Cover · 3 Problem** — intro, then the problem: too many logs, and AI alone makes things up.
- **P2 — 5 Rule · 6 How** — our rule "no evidence, no claim", then how it works end to end.
- **P3 — 8 Key strengths** — evidence you can trust, one query across 7 SIEMs, zero-code onboarding.
- **P4 — 10 Proof** — the numbers on real attack data: 100% accuracy, 0 false alarms, same answer every run.
- **P5 — 12 Why this approach · 13 Conclusion · 14 Team** — why drop it into an existing SOC, the takeaway
  ("threat hunting you can trust / an auditable AI"), and the team page.

> The pitch is grouped by talking order (smooth hand-offs); the report is grouped by code area.
> They don't line up slide-for-section — that's normal.

Code areas and their acceptance tests: see [`docs/OWNERSHIP.md`](OWNERSHIP.md).
