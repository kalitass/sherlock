"""Verification pass -- enforces "no evidence, no claim".

A finding is verified only if it cites evidence that:
  1. exists in this hunt's ledger (no hallucinated citation);
  2. came from a QUERY tool (count/search/aggregate), not a context tool;
  3. actually ran successfully (ok);
  4. matches the finding's role -- a positive finding needs a query that matched
     >=1 document; a negative finding (an absence claim) needs a query that ran
     and matched 0 documents.

Anything else is quarantined out of the verdict and shown in the report's
"rejected" section, so the guardrail is visible.
"""
from __future__ import annotations

from typing import Any

from core.evidence_ledger import EvidenceLedger

def _role(f: dict[str, Any]) -> str:
    # The role ("positive" presence vs "negative" absence) is a structured field the
    # engine sets: the LLM emits it (validated enum), the deterministic probes set it
    # explicitly. We never infer it from the claim's wording. A finding that arrives
    # without a valid role defaults to "positive" -- the stricter check (needs >=1 hit).
    role = (f.get("role") or "").lower()
    return role if role in ("positive", "negative") else "positive"


def verify_findings(findings: list[dict[str, Any]], ledger: EvidenceLedger) -> dict[str, Any]:
    """Accept a finding only when every citation is a supporting, successful query."""
    verified, rejected = [], []
    for finding in findings:
        finding = dict(finding)
        ids = finding.get("evidence_ids") or []
        role = _role(finding)
        cited = [(eid, ledger.get(eid)) for eid in ids]
        missing = [eid for eid, entry in cited if entry is None]
        context = [eid for eid, entry in cited if entry is not None and not entry.is_query_tool]
        queries = [entry for _, entry in cited if entry is not None and entry.is_query_tool]
        failed = [entry for entry in queries if not entry.ok]

        def supports(entry: Any) -> bool:
            matches = entry.matched_documents
            if not isinstance(matches, int):
                return False
            return matches == 0 if role == "negative" else matches > 0

        mismatch = [entry for entry in queries if entry.ok and not supports(entry)]
        reasons = []
        if not ids:
            reasons.append("no evidence cited")
        if missing:
            reasons.append(f"hallucinated citation: non-existent evidence {missing}")
        if context:
            reasons.append(f"context tools cannot support a claim: {context}")
        if failed:
            reasons.append("a cited query failed to execute or returned an unknown result")
        if mismatch:
            direction = "0 hits" if role == "negative" else ">=1 hit"
            reasons.append(f"a cited query did not match in the claim's direction (expected {direction})")

        finding["role"] = role
        finding["cited_matches"] = {
            eid: entry.matched_documents if entry is not None else None
            for eid, entry in cited
        }
        if not reasons:
            finding["verified"] = True
            verified.append(finding)
        else:
            finding["verified"] = False
            finding["reject_reason"] = "; ".join(reasons)
            rejected.append(finding)

    total = len(findings)
    return {
        "verified_findings": verified,
        "rejected_findings": rejected,
        "verification_rate": round(len(verified) / total, 3) if total else 1.0,
        "n_total": total,
        "n_verified": len(verified),
        "n_rejected": len(rejected),
    }
