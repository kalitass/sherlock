# Slot Contracts

The seams between the foundation (M1) and each member's slot. **Keep these
signatures and shapes identical** — they are what the rest of the system calls, so
honouring them means the platform keeps running as each slot is implemented. Each
slot's own file header has the same contract plus a TODO list and a demo-repo
reference.

## M2 — Schema Intelligence

```python
# ingestion/parsing.py
parse_record(schema: dict, raw: Any) -> dict | None      # doc carries @timestamp (UTC) + log_type
normalise_ts(value, fmt="auto") -> str | None            # ISO-8601 UTC  (FOUNDATION — keep)

# ingestion/auto_schema.py
detect_and_register(log_type, sample, source="unknown", use_llm=True) -> dict
#   returns: parser, ts_field, ts_format, field_map, validation{rate,...},
#            fingerprint, name, created_by, registered(bool), reused(bool)

# ingestion/schema_registry.py
fingerprint(sample, log_type="") -> str ; register(schema) -> schema
get_by_fingerprint(fp) -> dict | None ; list_schemas() -> list ; guess_es_type(field, value) -> str

# common/schemas.py        (enhance: the 7-schema compatibility + normalisation)
detect_schema(record, raw=None) -> str | None
normalise(record, schema) -> dict          # {n_time, n_event_id, n_host, n_user, n_src_ip, n_action, ...}
get_path(record, path) -> Any              # flat-dotted OR nested

# ingestion/schema_drift.py
check_drift(log_type, docs, siem_schema="") -> {"status": baseline|stable|drift|error, "missing", "type_changed", "added"}
```
The ingestion core calls `detect_and_register`, `parse_record`, `detect_schema`,
`normalise`, `check_drift`. Baselines make them safe; `normalise`/`detect_schema`/
`check_drift` are inert until you implement them.

## M3 — MCP & Tooling

```python
# mcp_server/tools.py          every query tool returns a uniform envelope:
#   {"ok": bool, "tool": str, "matched_documents": int, "es_request": {"index","body"}, ...}
QUERY_TOOLS = {"count_logs", "search_logs", "aggregate"}
call(name, args) -> envelope          # dispatch; unknown/err -> {"ok": False, "error": ...}

# hunt_engine/mcp_client.py
class MCPClient:  __enter__/__exit__ ; backend_name: str
    list_tools() -> [Tool(name, description, input_schema)]
    call(name, args) -> envelope      # fail-closed: transport error -> {"ok": False, ...}

# common/llm.py
class LLMClient:  available() -> bool ; complete(system, user) -> str
    complete_json(system, user) -> dict
    agent_loop(system, user, tools: [ToolSpec], max_turns=24, on_event) -> str
@dataclass ToolSpec: name, description, input_schema, fn

# common/providers.py
resolve_provider(provider=None) -> Resolved(available: bool, ...) ; list_providers() -> list
```
The hunt engine calls `MCPClient().call(...)` and `LLMClient().available()`.

## M4 — Hunt Engine

```python
# hunt_engine/evidence_ledger.py
class EvidenceLedger(hunt_id, persist=True):  entries: [Evidence] ; persist_errors: int
    record(name, args, result) -> Evidence ; get(eid) -> Evidence|None ; as_list() -> list
@dataclass Evidence: evidence_id, tool, arguments, is_query_tool, ok, matched_documents, es_request, result_summary, hit_count

# hunt_engine/verifier.py
verify_findings(findings, ledger) -> {"verified_findings","rejected_findings","n_verified","n_rejected","verification_rate"}

# hunt_engine/reduce.py
compute_coverage(ledger, engine_coverage) -> {"sources_searched","queries_ok","queries_failed","complete"}
reduce_verdict(hypothesis, candidate, verification, coverage, ledger, hypothesis_covered=True) -> {"verdict","confidence","summary"}

# hunt_engine/heuristic.py  /  llm_hunt.py
run_heuristic_hunt(hypothesis, client, ledger, on_event) -> result
run_llm_hunt(hypothesis, client, ledger, on_event) -> result
#   result: {"verdict","confidence","summary","findings":[{claim,evidence_ids,mitre,severity,role}],"coverage","engine"}

# hunt_engine/reporter.py
build_report(meta, result, verification, ledger) -> str   # Markdown
```

## The integration bundle (what the dashboard renders) — `hunt_engine/hunt.py`

```python
run_hunt(hypothesis, run_label=None, use_llm=None, on_event=None, persist=True, mcp_backend=None) -> {
  "meta":   {hunt_id, hypothesis, run_label, started_at, finished_at, mcp_backend, llm_available, engine_fallback},
  "result": {verdict, confidence, summary, findings, coverage, engine, candidate_verdict},
  "verification": {verified_findings, rejected_findings, n_verified, n_rejected, verification_rate},
  "report_md": str,
  "evidence": [ {evidence_id, tool, hit_count, es_request, result_summary} ],
}
```
`on_event({...})` streams: `start, mcp, probe, finding, warning, verdict, done`.

## M5 — Product, UX & Evaluation

```python
# dashboard/app.py (FastAPI)   GET / ; GET /api/overview ; POST /api/hunt
#   enhance: GET /api/hunt_stream (SSE live trace), verdict card, findings, ledger view
# datasets/scenarios.py   SCENARIOS={name:{host,gen,desc,hypothesis,expected}} ; build(name) -> [n_* events]
# experiment/run_twice.py run_experiment(hypothesis, use_llm=None) -> dict
```
