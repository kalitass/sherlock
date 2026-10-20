"""Mock data in the seven famous SIEM schemas (SE6014 Week 2) — "one event, seven
spellings". The same Operation-Nightjar logon activity is rendered in each schema
using the lecture's exact field names, so Sherlock's normalisation layer can map
them all back to one canonical shape and a single hunt fires across every one.

  Producer-side (wire):   cef.log   (ArcSight CEF)    leef.log  (IBM QRadar LEEF)
  Consumer-side (SIEM):   cim.json  (Splunk CIM)      ecs.json  (Elastic ECS)
                          ocsf.json (OCSF)            asim.json (MS Sentinel ASIM)
                          udm.json  (Google SecOps UDM)

Seeded → byte-identical across runs.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260915
DAY = datetime(2026, 9, 15, tzinfo=timezone.utc)
OUT = Path(__file__).resolve().parent / "generated" / "siem"

HOST = "WIN-APP01"
ATTACKER_IP = "203.0.113.66"
ADMIN = "administrator"
NEW_ACCT = "svc_backup"
USERS = ["alice", "bob", "carol", "dave", "erin"]
INTERNAL = ["10.10.20.30", "10.10.20.31", "10.10.20.42", "10.10.20.55"]


@dataclass
class Event:
    """One security event in schema-neutral terms; each renderer re-spells it."""
    t: datetime
    event_id: str          # Windows event code
    user: str
    src_ip: str
    outcome: str           # "failure" | "success"
    name: str
    sev: int


def _timeline(rng: random.Random) -> list[Event]:
    """Logon-only (4624/4625) so every schema is a clean Authentication example.
    The full kill chain (4720/4728, C2, …) lives in the native windows/sysmon/web
    data; here the point is the SAME logon event rendered across seven schemas."""
    ev: list[Event] = []
    def at(minute: float) -> datetime:
        # whole seconds, so every schema's timestamp encoding (epoch-ms vs ISO)
        # resolves to the SAME instant -> n_time matches across all seven.
        return (DAY + timedelta(hours=2, minutes=minute)).replace(microsecond=0)

    for _ in range(55):                      # benign successful logons across the hour
        ev.append(Event(at(rng.uniform(0, 59)), "4624", rng.choice(USERS),
                        rng.choice(INTERNAL), "success", "An account was successfully logged on", 2))
    for i in range(18):                      # brute force: 18 failed admin logons
        ev.append(Event(at(11 + i * 0.1), "4625", ADMIN, ATTACKER_IP, "failure",
                        "An account failed to log on", 7))
    ev.append(Event(at(16), "4624", ADMIN, ATTACKER_IP, "success",
                    "An account was successfully logged on", 2))
    rng.shuffle(ev)
    return ev


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


# --- renderers: one logon event -> each schema's REAL Authentication fields -------
# Timestamp encodings follow each standard: CEF/LEEF/CIM use epoch milliseconds,
# OCSF uses epoch ms, ECS and UDM use RFC 3339 strings.
def r_cef(e: Event) -> str:
    # Windows code in header SignatureID; result in `outcome`; `start` = activity time.
    outcome = "Failure" if e.outcome == "failure" else "Success"
    ext = (f"start={_epoch_ms(e.t)} rt={_epoch_ms(e.t)} dvchost={HOST} duser={e.user} "
           f"src={e.src_ip} outcome={outcome}")
    return f"CEF:0|NightjarCorp|WinSec|1.0|{e.event_id}|{e.name}|{e.sev}|{ext}"


def r_leef(e: Event) -> str:
    # LEEF 2.0 with an explicit tab delimiter header (x09); epoch-ms devTime; `cat`.
    cat = "Failed" if e.outcome == "failure" else "Success"
    ext = "\t".join([f"devTime={_epoch_ms(e.t)}", f"resource={HOST}", f"usrName={e.user}",
                     f"src={e.src_ip}", f"cat={cat}", f"sev={e.sev}"])
    return f"LEEF:2.0|NightjarCorp|WinSec|1.0|{e.event_id}|x09|{ext}"


def r_cim(e: Event) -> dict:     # Splunk CIM Authentication (_time = epoch seconds)
    return {"_time": int(e.t.timestamp()), "signature_id": e.event_id, "dest": HOST,
            "src": e.src_ip, "user": e.user, "action": e.outcome, "severity": e.sev,
            "signature": e.name, "app": "win:security"}


def r_ecs(e: Event) -> dict:     # Elastic ECS (RFC 3339 @timestamp)
    return {"@timestamp": _iso(e.t), "ecs.version": "8.11.0", "event.code": e.event_id,
            "event.kind": "event", "event.category": ["authentication"],
            "event.outcome": e.outcome, "event.severity": e.sev, "host.name": HOST,
            "user.name": e.user, "source.ip": e.src_ip}


def r_ocsf(e: Event) -> dict:    # OCSF Authentication (class_uid 3002, activity Logon)
    ok = e.outcome == "success"
    return {"time": _epoch_ms(e.t), "category_uid": 3, "class_uid": 3002, "activity_id": 1,
            "type_uid": 300201, "status": "Success" if ok else "Failure",
            "status_id": 1 if ok else 2, "severity_id": 2 if ok else 4,  # 2=Low/4=High, aligns 7-wide
            "metadata.event_code": e.event_id, "metadata.product.name": "Windows Security",
            "metadata.product.vendor_name": "Microsoft", "metadata.version": "1.3.0",
            "device.hostname": HOST, "dst_endpoint.hostname": HOST, "user.name": e.user,
            "src_endpoint.ip": e.src_ip}


def r_asim(e: Event) -> dict:    # Microsoft Sentinel ASIM Authentication
    ok = e.outcome == "success"
    return {"TimeGenerated": _iso(e.t), "EventStartTime": _iso(e.t), "EventEndTime": _iso(e.t),
            "EventSchema": "Authentication", "EventSchemaVersion": "1.0.0", "EventType": "Logon",
            "EventCount": 1, "EventProduct": "Security Events", "EventVendor": "Microsoft", "Dvc": HOST,
            "EventOriginalType": e.event_id, "TargetHostname": HOST, "TargetUsername": e.user,
            "SrcIpAddr": e.src_ip, "EventResult": "Success" if ok else "Failure",
            "EventSeverity": "Low" if ok else "High"}


def r_udm(e: Event) -> dict:     # Google SecOps UDM (client=principal, target=system; RFC 3339)
    ok = e.outcome == "success"
    return {"metadata.event_timestamp": _iso(e.t), "metadata.event_type": "USER_LOGIN",
            "metadata.product_event_type": e.event_id, "metadata.product_name": "Windows Security",
            "target.hostname": HOST, "target.user.userid": e.user, "principal.ip": e.src_ip,
            "extensions.auth.outcome": "SUCCESS" if ok else "FAILURE",
            "security_result.severity": "HIGH" if not ok else "LOW"}


def main() -> dict[str, int]:
    OUT.mkdir(parents=True, exist_ok=True)
    events = _timeline(random.Random(SEED))
    counts: dict[str, int] = {}

    for name, render in (("cef.log", r_cef), ("leef.log", r_leef)):
        (OUT / name).write_text("\n".join(render(e) for e in events) + "\n")
        counts[name] = len(events)

    for name, render in (("cim.json", r_cim), ("ecs.json", r_ecs), ("ocsf.json", r_ocsf),
                         ("asim.json", r_asim), ("udm.json", r_udm)):
        (OUT / name).write_text("\n".join(json.dumps(render(e)) for e in events) + "\n")
        counts[name] = len(events)

    return counts


if __name__ == "__main__":
    for k, v in main().items():
        print(f"{k:12s} {v:4d} events")
    print(f"\nWritten to {OUT}")
