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
    raise NotImplementedError(
        "TODO P5: verify each finding against the ledger: keep it only if every cited "
        "id exists, is a query tool, ran OK, and matched in the finding's direction "
        "(positive>=1 hit, negative=0); return verified/rejected split. "
        "Reference implementation: sherlock-demo/hunt_engine/verifier.py."
    )
