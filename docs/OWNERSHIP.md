# Ownership & Division of Labour (5 members)

Sherlock is split into a shared **`core/`** foundation plus five independently
implementable slices. Each member owns one slice: its directory, its section of the
report, and its part of the demo/pitch. **You implement your slice against the
reference implementation in the sibling `sherlock-demo/` repo** until your tests pass.

> **Dependency rule.** A `components/<x>/` package imports from `core` (contracts,
> settings, ES, the MCP tool surface), with one documented exception: **ingestion
> imports normalization** (the ingest pipeline normalises each record to `n_*`). That
> is the only inter-component edge; the graph is acyclic (`normalization` is a leaf),
> and `core` imports nothing from `components`. This is what lets five people work in
> parallel without merge collisions. Add no other component-to-component import.

## Who owns what

| Member | Owns (directories) | Builds | Report section | Demo / pitch |
|---|---|---|---|---|
| **P1 — Platform & orchestration** | `core/`, `app/`, CI | contracts, settings, ES client, LLM/provider client, evidence ledger, MCP server+tools+client, the hunt pipeline, CLI, dashboard | System architecture + reproducible setup | Bring up the stack; show the MCP tool surface |
| **P2 — Ingestion** | `components/ingestion/` | pull/push/stream, agentic auto-schema, parsing, schema registry, schema drift | Ingestion & auto-schema | Point at a public dataset → auto-schema onboards it |
| **P3 — Interoperability** | `components/normalization/`, `components/detection/` | 7-SIEM `n_*` normalization; Sigma rule migration | Interoperability (normalise-first, Sigma) | One query across 7 SIEM formats; import a Sigma rule |
| **P4 — Hunt engine** | `components/hunt/` | LLM agent loop + deterministic scanner | Agentic workflow design | Run a live hunt from a plain-English hypothesis |
| **P5 — Harness & evaluation** | `components/harness/`, `experiment/` | verifier + reducer; benchmark / repeatability / ablation | Guardrails + experiment results | Evidence gate rejects a claim live; present the numbers |

## Your definition of "done" = these tests turn green

The acceptance tests are already written (they are the spec). Run `make test`
(or `uv run --group dev pytest`). Stubs currently show as **xfail** (expected
failure); implementing your functions flips *your* tests to real passes.

| Member | Function(s) to implement | Tests that must pass |
|---|---|---|
| **P2** | `components/ingestion/parsing.py::parse_record`, `ingest_core.py::ingest_records`, `auto_schema.py::detect_and_register` | `test_core.py::{test_parse_json, test_parse_clf, test_parse_clf_rejects_partial_line, test_cef_leef_parse}`, `test_foundation.py::test_parse_json` |
| **P3 (normalization)** | `components/normalization/schemas.py::{detect_schema, normalise}` | `test_core.py::{test_schema_detection, test_normalise_all_seven_agree, test_normalise_nested_json_and_severity}` |
| **P3 (detection)** | `components/detection/sigma_import.py::migrate` | `test_sigma.py::*` (5 tests) |
| **P5** | `components/harness/verifier.py::verify_findings`, `reduce.py::reduce_verdict` | `test_core.py::{test_verifier_contract, test_verifier_multistage_requires_all_citations, test_verifier_unknown_match_is_not_zero, test_reduce_all_rejected_is_not_confirmed, test_reduce_tool_error_is_inconclusive, test_reduce_direction_from_supports, test_reduce_uncovered_is_inconclusive, test_reduce_no_findings_is_not_refuted, test_reduce_verified_absence_refutes}` |
| **P4** | `components/hunt/llm_hunt.py::run_llm_hunt`, `heuristic.py::run_heuristic_hunt` | Integration (needs live ES + LLM): `make hunt H="..."`. Return the `HuntResult` shape in `core/contracts.py`. |

Do **not** weaken a test to make it pass. The contract shapes live in
`core/contracts.py`; if you must change one, change it there and tell the other
owners.

## Effort note

Balance is across **code + report + demo**, not lines alone. P1 is lighter in new
code (much of `core` is provided) but owns repo setup, CI and architecture; P3 is
lighter in code but owns the interoperability story and its demo.
