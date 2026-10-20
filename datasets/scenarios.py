"""Extra test scenarios authored directly in Sherlock's CANONICAL (normalised)
schema — the `n_*` fields every SIEM source is mapped onto.

Because detection and hunting run on the canonical fields, a new scenario does not
need to be re-rendered in all seven SIEM dialects; we write it once in the
normalised shape. Each scenario lands in its own index (`sherlock-logs-scn_<name>`)
on its own host, so it can be hunted in isolation.

Scenarios
---------
- benign          : a normal day, NO attack  -> a hunt must NOT confirm an intrusion
                    (tests false positives / TPNA — SE6014 Week 2).
- password-spray  : one external IP, few attempts across MANY accounts (T1110.003),
                    distinct from Operation Nightjar's single-account brute force.
- data-exfil      : an after-hours insider archives and ships large volumes to an
                    external IP (T1560 + T1041).

Seeded -> byte-identical across runs.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

DAY = datetime(2026, 9, 15, tzinfo=timezone.utc)
FIN_USERS = ["jhsu", "mlee", "rtan", "kwong", "pgoh", "schen"]
HR_USERS = ["mallory", "ngan", "dwee", "lkoh"]
INTERNAL = ["10.20.10.31", "10.20.10.44", "10.20.10.52", "10.20.10.63"]


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ev(**kw: Any) -> dict[str, Any]:
    """A canonical event; only n_* keys so nothing needs re-normalising."""
    kw.setdefault("n_schema", "canonical")
    return kw


# --------------------------------------------------------------------------- #
# benign — a normal working day, no attack signal at all.
# --------------------------------------------------------------------------- #
def gen_benign(rng: random.Random) -> list[dict]:
    host = "WIN-FIN03"
    out: list[dict] = []
    for _ in range(70):                      # normal interactive logons (09:00-18:00)
        t = DAY + timedelta(hours=9, minutes=rng.uniform(0, 540))
        out.append(_ev(n_time=_iso(t), n_host=host, n_user=rng.choice(FIN_USERS),
                       n_src_ip=rng.choice(INTERNAL), n_event_id="4624", n_action="success",
                       n_message="interactive logon"))
    for _ in range(50):                      # normal office processes
        t = DAY + timedelta(hours=9, minutes=rng.uniform(0, 540))
        proc = rng.choice(["outlook.exe", "excel.exe", "chrome.exe", "teams.exe", "onedrive.exe"])
        out.append(_ev(n_time=_iso(t), n_host=host, n_user=rng.choice(FIN_USERS),
                       n_process=proc, n_parent="explorer.exe", n_action="success",
                       n_message="process start"))
    rng.shuffle(out)
    return out


# --------------------------------------------------------------------------- #
# password-spray — one external IP, a few tries each across MANY accounts.
# --------------------------------------------------------------------------- #
def gen_password_spray(rng: random.Random) -> list[dict]:
    host = "WIN-VPN01"
    attacker = "198.51.100.77"
    sprayed = FIN_USERS + HR_USERS + ["admin", "svc_sql", "backup", "guest", "helpdesk"]
    out: list[dict] = []
    for _ in range(30):                      # benign baseline logons
        t = DAY + timedelta(hours=8, minutes=rng.uniform(0, 300))
        out.append(_ev(n_time=_iso(t), n_host=host, n_user=rng.choice(FIN_USERS),
                       n_src_ip=rng.choice(INTERNAL), n_event_id="4624", n_action="success",
                       n_message="vpn logon"))
    base = DAY + timedelta(hours=3)          # the spray: broad, low-and-slow, one source
    for i, user in enumerate(sprayed):
        for j in range(rng.randint(1, 2)):   # only 1-2 tries per account = spray, not brute
            t = base + timedelta(minutes=i * 1.5 + j * 0.3)
            out.append(_ev(n_time=_iso(t), n_host=host, n_user=user, n_src_ip=attacker,
                           n_event_id="4625", n_action="failure", n_message="failed logon"))
    out.append(_ev(n_time=_iso(base + timedelta(minutes=26)), n_host=host, n_user="helpdesk",
                   n_src_ip=attacker, n_event_id="4624", n_action="success",
                   n_message="logon success after spray"))
    rng.shuffle(out)
    return out


# --------------------------------------------------------------------------- #
# data-exfil — an after-hours insider archives data and ships it out.
# --------------------------------------------------------------------------- #
def gen_data_exfil(rng: random.Random) -> list[dict]:
    host = "WIN-HR02"
    insider = "mallory"
    dest = "203.0.113.88"
    out: list[dict] = []
    for _ in range(40):                      # benign HR activity during the day
        t = DAY + timedelta(hours=10, minutes=rng.uniform(0, 420))
        out.append(_ev(n_time=_iso(t), n_host=host, n_user=rng.choice(HR_USERS),
                       n_src_ip=rng.choice(INTERNAL), n_event_id="4624", n_action="success",
                       n_message="hr app logon"))
    base = DAY + timedelta(hours=2, minutes=10)   # after hours
    out.append(_ev(n_time=_iso(base), n_host=host, n_user=insider, n_process="powershell.exe",
                   n_parent="explorer.exe", n_cmdline="powershell -c Get-ChildItem \\\\hr-fileshare",
                   n_action="success", n_message="after-hours share enumeration"))
    out.append(_ev(n_time=_iso(base + timedelta(minutes=3)), n_host=host, n_user=insider,
                   n_process="7z.exe", n_parent="powershell.exe",
                   n_cmdline="7z a -p hr_dump.7z \\\\hr-fileshare\\payroll",
                   n_action="success", n_message="staging: archive created"))
    for i in range(16):                      # many large outbound transfers to one external IP
        t = base + timedelta(minutes=8 + i * 1.5)
        out.append(_ev(n_time=_iso(t), n_host=host, n_user=insider, n_process="rclone.exe",
                       n_parent="powershell.exe", n_src_ip="10.20.30.12", n_dst_ip=dest,
                       n_dst_port="443", n_bytes=rng.randint(80_000_000, 420_000_000),
                       n_action="success", n_message="large outbound transfer"))
    rng.shuffle(out)
    return out


SCENARIOS: dict[str, dict[str, Any]] = {
    "benign": {
        "host": "WIN-FIN03", "gen": gen_benign,
        "desc": "A normal working day with no attack — hunting it must NOT confirm an intrusion.",
        "hypothesis": "Was WIN-FIN03 compromised by an external attacker?",
        "expected": "inconclusive / refuted (no attack present — a false-positive test)",
    },
    "password-spray": {
        "host": "WIN-VPN01", "gen": gen_password_spray,
        "desc": "One external IP tries a few passwords across many accounts (T1110.003).",
        "hypothesis": "Did an external IP run a password-spray against many accounts on WIN-VPN01?",
        "expected": "confirmed — one src IP, failures across many distinct users, then one success",
    },
    "data-exfil": {
        "host": "WIN-HR02", "gen": gen_data_exfil,
        "desc": "An after-hours insider archives HR data and ships it to an external IP (T1560+T1041).",
        "hypothesis": "Did an insider on WIN-HR02 stage and exfiltrate data to an external host after hours?",
        "expected": "confirmed — 7z archive then repeated large rclone transfers to an external IP",
    },
}


def build(name: str, seed: int = 20260915) -> list[dict]:
    if name not in SCENARIOS:
        raise KeyError(f"unknown scenario '{name}'; have {list(SCENARIOS)}")
    return SCENARIOS[name]["gen"](random.Random(seed))


if __name__ == "__main__":
    for n in SCENARIOS:
        print(f"{n:16s} {len(build(n)):4d} events  — {SCENARIOS[n]['desc']}")
