"""Foundation (M1) unit tests — pure logic, no live ES needed.

These lock the ingestion CONTRACT that every other member builds against. Keep them
green. Members 2-5 add their own tests as they implement their slots.

Run:  uv run python -m tests.test_foundation
"""
from __future__ import annotations

from components.ingestion.parsing import parse_record, normalise_ts
from components.ingestion import schema_registry as reg


def test_parse_json():
    schema = {"parser": {"kind": "json"}, "ts_field": "@timestamp", "ts_format": "auto", "log_type": "windows"}
    doc = parse_record(schema, {"@timestamp": "2026-09-15T02:11:00.000Z", "event_id": 4625})
    assert doc and doc["log_type"] == "windows" and doc["event_id"] == 4625 and doc["@timestamp"].endswith("Z")
    print("ok  test_parse_json")


def test_normalise_ts():
    assert (normalise_ts("2026-09-15T02:11:00Z") or "").startswith("2026-09-15T02:11:00")
    assert (normalise_ts(1757900000, "epoch") or "").startswith("2025-")
    assert normalise_ts(None) is None
    print("ok  test_normalise_ts")


def test_fingerprint_stable():
    a = reg.fingerprint([{"a": 1, "b": 2}], "win")
    b = reg.fingerprint([{"b": 9, "a": 8}], "win")      # same key set
    c = reg.fingerprint([{"a": 1, "c": 3}], "win")      # different keys
    assert a == b and a != c
    print("ok  test_fingerprint_stable")


def test_guess_es_type():
    assert reg.guess_es_type("src_ip", "10.0.0.1") == "ip"
    assert reg.guess_es_type("event_id", 4625) == "long"
    assert reg.guess_es_type("user", "alice") == "keyword"
    print("ok  test_guess_es_type")


def main():
    for fn in [test_parse_json, test_normalise_ts, test_fingerprint_stable, test_guess_es_type]:
        fn()
    print("\nAll foundation tests passed.")


if __name__ == "__main__":
    main()
