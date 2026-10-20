"""Cross-component contracts for Sherlock.

`core` is the foundation every component depends on; no component imports another
component. These TypedDicts are the shapes that cross a component boundary, so an
implementer of one component can build against them without reading another's code:

    ingestion ─▶ ES ◀─ MCP tools ◀─ hunt (findings) ─▶ harness (verify+reduce) ─▶ verdict

Nothing here is enforced at runtime (Python TypedDicts are structural hints); they
are the written interface. If you change a shape, change it HERE and tell the other
owners — that is the whole point of putting it in `core`.
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

# --- vocabulary -------------------------------------------------------------
Verdict = Literal["confirmed", "refuted", "inconclusive"]
Severity = Literal["low", "medium", "high", "critical"]
Role = Literal["positive", "negative"]        # GRAMMAR of a claim (presence vs absence)

# The only MCP tools whose result may back a finding (query tools). Context tools
# (list_log_types / get_field_mapping / sample_logs) never support a claim.
QUERY_TOOLS: frozenset[str] = frozenset({"count_logs", "search_logs", "aggregate"})


# --- what the hunt engine (components/hunt) emits ---------------------------
class Finding(TypedDict, total=False):
    claim: str
    evidence_ids: list[str]            # ids returned by tool calls, e.g. ["E3", "E7"]
    mitre: str                         # ATT&CK id, e.g. "T1110"
    technique: str                     # human name
    severity: Severity
    role: Role                         # positive = asserts presence (cite a >=1-hit query);
                                       # negative = asserts absence (cite a 0-hit query)
    addresses_hypothesis: bool         # does this finding bear on THIS hypothesis at all?
    supports_hypothesis: bool          # does it argue the hypothesis (as stated) is TRUE?


class HuntResult(TypedDict, total=False):
    verdict: Verdict                   # the engine's self-report (candidate)
    confidence: float                  # 0..1
    summary: str
    hypothesis_polarity: Literal["affirmative", "negated"]
    findings: list[Finding]
    coverage: dict[str, Any]           # {sources_searched, techniques_considered, ...}
    recommended_actions: list[str]
    engine: str                        # "llm:<model>" | "heuristic"
    hypothesis_covered: bool           # did the engine actually probe this hypothesis?


# --- what the harness (components/harness) returns --------------------------
class Verification(TypedDict):
    verified_findings: list[Finding]   # every cited query exists, is a query tool, ran, matched direction
    rejected_findings: list[Finding]   # each carries a "reject_reason"
    verification_rate: float           # n_verified / n_total
    n_total: int
    n_verified: int
    n_rejected: int


class ReducedVerdict(TypedDict):
    verdict: Verdict                   # re-derived from VERIFIED, addressing findings — not the engine's word
    confidence: float
    candidate_verdict: Verdict         # kept for transparency; never trusted
    hypothesis_polarity: Literal["affirmative", "negated"]
    hypothesis_covered: bool
    summary: str


# --- the uniform MCP tool envelope (core/mcp/tools) -------------------------
class ToolResult(TypedDict, total=False):
    ok: bool
    tool: str
    matched_documents: int             # query tools only
    es_request: dict[str, Any]         # {index, body} — makes every claim reproducible
    error: str                         # present iff ok is False
