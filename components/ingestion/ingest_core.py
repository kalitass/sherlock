"""Shared ingestion core used by all three modes (pull / push / stream).

Flow for any batch of raw records:
  detect-or-reuse schema  ->  ensure index mapping  ->  parse  ->  bulk index
  ->  write an ingest-audit record (provenance).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.es import bulk_index, ensure_log_index, index_doc
from components.normalization.schemas import detect_schema, normalise
from core.settings import INGEST_AUDIT_INDEX, log_index
from components.ingestion.auto_schema import detect_and_register
from components.ingestion.parsing import parse_record
from components.ingestion.schema_drift import check_drift


def guess_log_type(name: str) -> str:
    n = name.lower()
    if "sysmon" in n:
        return "sysmon"
    if "win" in n or "security" in n or "evtx" in n:
        return "windows"
    if any(k in n for k in ("web", "access", "nginx", "apache", "http")):
        return "web"
    return Path(name).stem.replace(".", "_")


def read_raw_file(path: Path) -> tuple[str, list[Any]]:
    text = path.read_text(errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    log_type = guess_log_type(path.name)
    # NDJSON if every (sampled) line parses as a JSON object.
    def _is_json(ln: str) -> bool:
        try:
            return isinstance(json.loads(ln), dict)
        except Exception:
            return False

    if lines and all(_is_json(ln) for ln in lines[:20]):
        return log_type, [json.loads(ln) for ln in lines]
    return log_type, lines


def _maybe_json(r: Any) -> Any:
    """Turn a JSON-object string into a dict (NDJSON lines arriving over push/
    stream); leave everything else as-is."""
    if isinstance(r, str):
        s = r.strip()
        if s[:1] == "{":
            try:
                v = json.loads(s)
                if isinstance(v, dict):
                    return v
            except Exception:
                pass
    return r


def ingest_records(
    log_type: str, raw_records: list[Any], source: str, mode: str,
    refresh: bool = True, use_llm: bool = True,
) -> dict[str, Any]:
    raise NotImplementedError(
        "TODO P2: detect/register schema on a sample, ensure the index, parse each "
        "record, normalise to n_* when a SIEM schema is detected, bulk-index, and "
        "return the ingest summary dict. "
        "Reference implementation: sherlock-demo/ingestion/ingest_core.py."
    )


def ingest_file(path: Path, mode: str = "pull", refresh: bool = True, use_llm: bool = True) -> dict[str, Any]:
    log_type, records = read_raw_file(path)
    return ingest_records(log_type, records, source=str(path), mode=mode, refresh=refresh, use_llm=use_llm)


def _audit(summary: dict[str, Any]) -> None:
    try:
        index_doc(INGEST_AUDIT_INDEX, {
            "source": summary["source"], "mode": summary["mode"], "log_type": summary["log_type"],
            "schema_name": summary["schema_name"], "record_count": summary["count_indexed"],
            "ok": summary["ok"], "detail": f"in={summary['count_in']} failures={summary['failures']} "
                                            f"reused={summary['schema_reused']}",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass
