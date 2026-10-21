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
the architecture, run, data and configuration details.

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
