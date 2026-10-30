"""Deterministic (no-LLM) hunt engine -- a SCANNER.

A no-LLM engine cannot understand natural language, so it does NOT interpret the
hypothesis and never keyword-matches it (interpreting a free-text hypothesis is the
LLM engine's job). Instead it scans the data for every known attack pattern and
reports what it finds. This makes it a repeatable, audit-grade detection pass -- the
kind of thing you run on a schedule -- rather than a hypothesis answerer.

Two layers:

- **Probe primitives** -- a battery of atomic SOC detections, each tagged to MITRE
  ATT&CK and run through the same MCP tools + evidence ledger as the LLM path. A
  probe returns (finding, ok, absence); `ok` is False if any of its queries failed,
  so a query error is never silently read as "no attack". ALL probes run and report.
- **Scenarios** -- a scenario is a kill-chain: an ordered set of STAGES, each stage
  reusing a probe primitive and labelled with its ATT&CK tactic. After the probes
  run, each scenario composes the stages that fired into one multi-stage finding that
  narrates the kill-chain (Credential Access -> Initial Access -> Persistence -> ...),
  cites every fired stage's evidence, and is emitted only when >= 2 stages fired (one
  isolated technique is not a kill-chain) -- so the scan tells an attack *story*.

The candidate verdict is about the SCAN: `confirmed` when attack activity is detected,
`refuted` when the scan ran clean, `inconclusive` when it could not run. The final
verdict is still derived by hunt.reduce_verdict from verified evidence.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Callable

from core.evidence_ledger import EvidenceLedger
from core.mcp.client import MCPClient

EXTERNAL = ("NOT source_ip:[10.0.0.0 TO 10.255.255.255] "
            "AND NOT source_ip:[172.16.0.0 TO 172.31.255.255] "
            "AND NOT source_ip:[192.168.0.0 TO 192.168.255.255]")
EXTERNAL_DEST = EXTERNAL.replace("source_ip", "dest_ip")

WIN = "sherlock-logs-windows"
SYS = "sherlock-logs-sysmon"
WEB = "sherlock-logs-web"
BRUTE_THRESHOLD = 20   # a burst against one account, not fat-fingering
BEACON_THRESHOLD = 8

# (positive finding | None, ok, absence finding | None)
ProbeResult = tuple[dict[str, Any] | None, bool, dict[str, Any] | None]


class Probe:
    def __init__(self, pid, name, mitre, technique, severity,
                 run: Callable[[MCPClient, EvidenceLedger], ProbeResult]):
        self.pid, self.name, self.mitre, self.technique = pid, name, mitre, technique
        self.severity, self.run = severity, run


def _finding(claim, evidence_ids, mitre, technique, severity, detail=""):
    return {"claim": claim, "evidence_ids": evidence_ids, "mitre": mitre, "technique": technique,
            "severity": severity, "detail": detail, "role": "positive"}


def _absence(claim, evidence_ids, mitre, technique):
    return {"claim": claim, "evidence_ids": evidence_ids, "mitre": mitre, "technique": technique,
            "severity": "low", "detail": "", "role": "negative"}


def _ok(r: Any) -> bool:
    return isinstance(r, dict) and r.get("ok") is True


def _matched(r: dict) -> int:
    m = r.get("matched_documents", r.get("count"))
    return m if isinstance(m, int) and m >= 0 else 0


def _clean_zero(r: dict) -> bool:
    """The query ran successfully and matched exactly zero -- a real absence."""
    return _ok(r) and isinstance(r.get("matched_documents", r.get("count")), int) and _matched(r) == 0


def _buckets(r: dict) -> list[dict]:
    return r.get("result", {}).get("buckets", [])


# --- probes (each records its own evidence and returns (finding, ok)) -------
def _brute_force(c, led) -> ProbeResult:
    agg = c.call("aggregate", {"index": WIN, "field": "source_ip", "agg_type": "terms",
                               "query_string": "event_id:4625", "size": 10})
    ev = led.record("aggregate", {"probe": "brute_force"}, agg)
    if not _ok(agg):
        return None, False, None
    heavy = [b for b in _buckets(agg) if b["count"] >= BRUTE_THRESHOLD]
    if not heavy:
        return None, True, None    # below threshold is not a clean absence -> no assertion
    ips = ", ".join(f"{b['key']} ({b['count']} failures)" for b in heavy)
    return _finding(f"Password brute-force detected: {ips}.", [ev.evidence_id],
                    "T1110", "Brute Force", "high"), True, None


def _brute_force_success(c, led) -> ProbeResult:
    agg = c.call("aggregate", {"index": WIN, "field": "source_ip", "agg_type": "terms",
                               "query_string": f"event_id:4625 AND ({EXTERNAL})", "size": 10})
    ev_agg = led.record("aggregate", {"probe": "brute_force_failures"}, agg)
    if not _ok(agg):
        return None, False, None
    heavy = [b["key"] for b in _buckets(agg) if b["count"] >= BRUTE_THRESHOLD]
    winners, ids, ok = [], [], True
    for ip in heavy[:3]:
        lastf = c.call("search_logs", {"index": WIN, "query_string": f'event_id:4625 AND source_ip:"{ip}"',
                                       "sort": "desc", "size": 1, "fields": ["@timestamp"]})
        ev_lf = led.record("search_logs", {"probe": "last_failure", "ip": ip}, lastf)
        if not _ok(lastf) or _matched(lastf) == 0:
            ok = ok and _ok(lastf)
            continue
        t_last = lastf["hits"][0].get("@timestamp")
        # a successful logon at/after the END of the failure burst = credential success
        succ = c.call("count_logs", {"index": WIN, "query_string": f'event_id:4624 AND source_ip:"{ip}"',
                                     "start": t_last})
        ev_s = led.record("count_logs", {"probe": "logon_after_burst", "ip": ip}, succ)
        if not _ok(succ):
            ok = False
            continue
        if _matched(succ) > 0:
            winners.append(ip)
            ids += [ev_agg.evidence_id, ev_lf.evidence_id, ev_s.evidence_id]
    if not winners:
        return None, ok, None
    return _finding(f"Brute-force led to a successful logon from {', '.join(winners)}: a burst of >= "
                    f"{BRUTE_THRESHOLD} failed logons from the external IP, then a 4624 success from the "
                    "same IP at/after the burst ended.",
                    ids, "T1110", "Brute Force -> Valid Accounts", "critical"), ok, None


def _external_admin_logon(c, led) -> ProbeResult:
    r = c.call("count_logs", {"index": WIN,
                              "query_string": f"event_id:4624 AND target_user:administrator AND ({EXTERNAL})"})
    ev = led.record("count_logs", {"probe": "external_admin_logon"}, r)
    if not _ok(r):
        return None, False, None
    if _matched(r) > 0:
        return _finding(f"Privileged (administrator) network logon from an external IP: {_matched(r)} event(s).",
                        [ev.evidence_id], "T1078", "Valid Accounts", "high"), True, None
    return None, True, _absence("No external administrator network logon was found.",
                                [ev.evidence_id], "T1078", "Valid Accounts")


def _new_admin_account(c, led) -> ProbeResult:
    created = c.call("search_logs", {"index": WIN, "query_string": "event_id:4720", "size": 10,
                                     "fields": ["@timestamp", "target_user"]})
    ev1 = led.record("search_logs", {"probe": "account_created"}, created)
    added = c.call("search_logs", {"index": WIN, "query_string": "event_id:4728", "size": 10,
                                   "fields": ["@timestamp", "target_user", "group_name"]})
    ev2 = led.record("search_logs", {"probe": "group_add"}, added)
    if not (_ok(created) and _ok(added)):
        return None, False, None
    cu = {h.get("target_user") for h in created.get("hits", []) if h.get("target_user")}
    au = {h.get("target_user") for h in added.get("hits", []) if h.get("target_user")}
    same = cu & au
    if _matched(created) > 0 and _matched(added) > 0 and same:
        return _finding(f"Account(s) created AND added to a privileged group -- same user: "
                        f"{', '.join(sorted(same))} -- persistence.",
                        [ev1.evidence_id, ev2.evidence_id], "T1136.001/T1098",
                        "Create Account / Account Manipulation", "high"), True, None
    if _matched(created) > 0:
        return _finding(f"New user account(s) created: {_matched(created)} event(s).",
                        [ev1.evidence_id], "T1136.001", "Create Account", "medium"), True, None
    if _matched(added) > 0:
        return _finding(f"Member(s) added to a privileged group: {', '.join(sorted(au)) or 'n/a'}.",
                        [ev2.evidence_id], "T1098", "Account Manipulation", "medium"), True, None
    if _clean_zero(created) and _clean_zero(added):
        return None, True, _absence("No new account creation or privileged-group additions were found.",
                                    [ev1.evidence_id, ev2.evidence_id], "T1136/T1098",
                                    "Create Account / Account Manipulation")
    return None, True, None


def _log_cleared(c, led) -> ProbeResult:
    r = c.call("count_logs", {"index": WIN, "query_string": "event_id:1102"})
    ev = led.record("count_logs", {"probe": "log_cleared"}, r)
    if not _ok(r):
        return None, False, None
    if _matched(r) > 0:
        return _finding(f"Security audit log was cleared ({_matched(r)} event(s)) -- anti-forensics.",
                        [ev.evidence_id], "T1070.001", "Indicator Removal: Clear Windows Event Logs", "high"), True, None
    return None, True, _absence("No Windows security-log clearing (1102) was found.",
                                [ev.evidence_id], "T1070.001", "Indicator Removal")


def _encoded_powershell(c, led) -> ProbeResult:
    r = c.call("search_logs", {"index": SYS, "query_string": "event_id:1 AND command_line:*enc*",
                               "size": 5, "fields": ["@timestamp", "image", "parent_image", "command_line"]})
    ev = led.record("search_logs", {"probe": "encoded_powershell"}, r)
    if not _ok(r):
        return None, False, None
    if _matched(r) > 0:
        return _finding(f"Encoded/obfuscated PowerShell execution observed ({_matched(r)} process event(s)), "
                        "consistent with a downloader/stager.", [ev.evidence_id],
                        "T1059.001", "PowerShell", "high"), True, None
    return None, True, _absence("No encoded/obfuscated PowerShell execution was found.",
                                [ev.evidence_id], "T1059.001", "PowerShell")


def _webshell(c, led) -> ProbeResult:
    r = c.call("search_logs", {"index": WEB, "query_string": "method:POST AND path:*uploads*",
                               "size": 5, "fields": ["@timestamp", "client_ip", "method", "path", "status"]})
    ev = led.record("search_logs", {"probe": "webshell"}, r)
    if not _ok(r):
        return None, False, None
    if _matched(r) > 0:
        ips = ", ".join(sorted({h.get("client_ip") for h in r.get("hits", []) if h.get("client_ip")}))
        return _finding(f"Repeated POSTs to an uploads path ({_matched(r)} request(s) from {ips}) -- web shell.",
                        [ev.evidence_id], "T1505.003", "Web Shell", "critical"), True, None
    return None, True, _absence("No POSTs to an uploads path (web-shell pattern) were found.",
                                [ev.evidence_id], "T1505.003", "Web Shell")


def _web_exploit(c, led) -> ProbeResult:
    r = c.call("count_logs", {"index": WEB,
                              "query_string": "path:*passwd* OR path:*1=1* OR path:*.git* OR path:*admin*"})
    ev = led.record("count_logs", {"probe": "web_exploit"}, r)
    if not _ok(r):
        return None, False, None
    if _matched(r) > 0:
        return _finding(f"Web reconnaissance / exploitation probes (traversal, SQLi, config access): "
                        f"{_matched(r)} request(s).", [ev.evidence_id],
                        "T1190", "Exploit Public-Facing Application", "medium"), True, None
    return None, True, _absence("No web reconnaissance / exploitation probes were found.",
                                [ev.evidence_id], "T1190", "Exploit Public-Facing Application")


def _c2_beacon(c, led) -> ProbeResult:
    agg = c.call("aggregate", {"index": SYS, "field": "dest_ip", "agg_type": "terms",
                               "query_string": f"event_id:3 AND ({EXTERNAL_DEST})", "size": 10})
    ev = led.record("aggregate", {"probe": "c2_egress"}, agg)
    if not _ok(agg):
        return None, False, None
    beacons = [b for b in _buckets(agg) if b["count"] >= BEACON_THRESHOLD]
    if not beacons:
        return None, True, None    # below threshold is not a clean absence
    ids = [ev.evidence_id]
    top = beacons[0]["key"]
    hist = c.call("aggregate", {"index": SYS, "field": "@timestamp", "agg_type": "date_histogram",
                                "interval": "5m", "query_string": f'event_id:3 AND dest_ip:"{top}"'})
    ev_h = led.record("aggregate", {"probe": "c2_periodicity"}, hist)
    recurring = _ok(hist) and hist.get("bucket_count", 0) >= 3
    if _ok(hist) and _matched(hist) > 0:
        ids.append(ev_h.evidence_id)
    dns = c.call("search_logs", {"index": SYS, "query_string": "event_id:22 AND NOT query_name:*microsoft* "
                 "AND NOT query_name:*google* AND NOT query_name:*office* AND NOT query_name:*corp.internal*",
                 "size": 5, "fields": ["@timestamp", "query_name", "query_results"]})
    ev2 = led.record("search_logs", {"probe": "c2_dns"}, dns)
    extra = ""
    if _ok(dns) and _matched(dns) > 0:
        ids.append(ev2.evidence_id)
        domains = ", ".join(sorted({h.get("query_name") for h in dns.get("hits", []) if h.get("query_name")}))
        extra = f" Newly observed domain(s) queried: {domains}."
    dests = ", ".join(f"{b['key']} ({b['count']} connections)" for b in beacons)
    shape = "recurring egress" if recurring else "repeated egress"
    return _finding(f"{shape.capitalize()} to external host(s) consistent with C2 beaconing: {dests}.{extra}",
                    ids, "T1071/T1571", "Command and Control", "critical"), True, None


PROBES: list[Probe] = [
    Probe("brute_force", "Password brute force", "T1110", "Brute Force", "high", _brute_force),
    Probe("brute_force_success", "Successful brute force", "T1110", "Brute Force -> Valid Accounts", "critical", _brute_force_success),
    Probe("external_admin_logon", "External admin logon", "T1078", "Valid Accounts", "high", _external_admin_logon),
    Probe("new_admin_account", "Persistence account", "T1136/T1098", "Create Account / Manipulation", "high", _new_admin_account),
    Probe("log_cleared", "Log clearing", "T1070", "Indicator Removal", "high", _log_cleared),
    Probe("encoded_powershell", "Encoded PowerShell", "T1059.001", "PowerShell", "high", _encoded_powershell),
    Probe("webshell", "Web shell", "T1505.003", "Web Shell", "critical", _webshell),
    Probe("web_exploit", "Web exploitation", "T1190", "Exploit Public-Facing App", "medium", _web_exploit),
    Probe("c2_beacon", "C2 beaconing", "T1071", "Command and Control", "critical", _c2_beacon),
]

_LEGACY_INDEX = {"brute_force": WIN, "brute_force_success": WIN,
                 "external_admin_logon": WIN, "new_admin_account": WIN,
                 "log_cleared": WIN, "encoded_powershell": SYS,
                 "webshell": WEB, "web_exploit": WEB, "c2_beacon": SYS}

PROBE_BY_ID: dict[str, Probe] = {p.pid: p for p in PROBES}


# Raw OTRF Security-Datasets probes from the reference implementation.
_MORDOR_SPECS = [
    ("account_creation", "EventID:4720", "T1136.001", "Create Account: Local Account", "high",
     "Local user account creation observed (Security 4720)",
     "No local-account-creation events were found."),
    ("scheduled_task", 'CommandLine:*schtasks* AND CommandLine:*Create*', "T1053.005", "Scheduled Task", "high",
     "Scheduled-task creation via schtasks observed",
     "No scheduled-task creation was found."),
    ("script_exec", "Image:*wscript.exe* OR Image:*cscript.exe*", "T1059.005",
     "Command and Scripting Interpreter: Visual Basic", "high",
     "Windows Script Host (wscript/cscript) execution observed",
     "No Windows Script Host execution was found."),
    ("encoded_powershell", "CommandLine:*-enc* OR CommandLine:*FromBase64String* OR CommandLine:*-EncodedCommand*",
     "T1059.001", "PowerShell", "high",
     "Encoded/obfuscated PowerShell execution observed",
     "No encoded PowerShell execution was found."),
    ("lsass_access", "EventID:10 AND TargetImage:*lsass.exe*", "T1003.001",
     "OS Credential Dumping: LSASS Memory", "critical",
     "A process opened a handle to LSASS memory (Sysmon 10)",
     "No LSASS process-access events were found."),
    ("sam_dump", "CommandLine:*esentutl* OR CommandLine:*\\\\SAM*", "T1003.002",
     "OS Credential Dumping: Security Account Manager", "critical",
     "SAM hive copy observed (esentutl / shadow copy)",
     "No SAM-hive copy was found."),
    ("lsa_secrets", "CommandLine:*reg* AND CommandLine:*secrets*", "T1003.004",
     "OS Credential Dumping: LSA Secrets", "critical",
     "LSA secrets dump via reg save observed",
     "No LSA-secrets dump was found."),
    ("disable_eventlog", "TargetObject:*Services*EventLog* OR TargetObject:*EventLog*Start*", "T1562.002",
     "Impair Defenses: Disable Windows Event Logging", "high",
     "Registry tampering with the Windows EventLog service observed",
     "No EventLog-service tampering was found."),
    ("disable_firewall", "CommandLine:*netsh* AND CommandLine:*firewall*", "T1562.004",
     "Impair Defenses: Disable or Modify System Firewall", "high",
     "Firewall modification via netsh observed",
     "No firewall modification was found."),
    ("log_cleared", "EventID:1102 OR EventID:104", "T1070.001",
     "Indicator Removal: Clear Windows Event Logs", "high",
     "Windows event log was cleared (1102/104)",
     "No event-log clearing was found."),
    ("group_discovery", "CommandLine:*localgroup*", "T1069.001",
     "Permission Groups Discovery: Local Groups", "medium",
     "Local-group enumeration (net localgroup) observed",
     "No local-group enumeration was found."),
    ("uac_bypass", "Image:*fodhelper.exe* OR CommandLine:*fodhelper*", "T1548.002",
     "Abuse Elevation Control Mechanism: Bypass UAC", "high",
     "UAC-bypass via fodhelper observed",
     "No UAC-bypass via fodhelper was found."),
    ("service_mod", "CommandLine:*sc* AND CommandLine:*config* AND CommandLine:*binPath*", "T1543.003",
     "Create or Modify System Process: Windows Service", "high",
     "Windows service reconfiguration (sc config binPath) observed",
     "No service reconfiguration was found."),
    ("proxy_mshta", "Image:*mshta.exe* OR CommandLine:*mshta*", "T1218.005",
     "System Binary Proxy Execution: Mshta", "high",
     "Signed-binary proxy execution via mshta observed",
     "No mshta proxy execution was found."),
    ("remote_service", "EventID:7045 OR EventID:4697", "T1021.002",
     "Remote Services: SMB/Windows Admin Shares", "high",
     "Windows service installation observed (7045/4697)",
     "No service-installation events were found."),
]

# --- scenario layer: kill-chains composed of probe primitives ---------------
@dataclass
class Stage:
    probe: str        # a probe id (the primitive this stage reuses)
    tactic: str       # the ATT&CK tactic / kill-chain phase this stage represents


@dataclass
class Scenario:
    sid: str
    name: str
    stages: list[Stage]   # in kill-chain order


SCENARIOS: list[Scenario] = [
    Scenario("hands_on_intrusion", "hands-on-keyboard intrusion",
             [Stage("brute_force", "Credential Access"),
              Stage("brute_force_success", "Initial Access"),
              Stage("external_admin_logon", "Initial Access"),
              Stage("encoded_powershell", "Execution"),
              Stage("new_admin_account", "Persistence"),
              Stage("log_cleared", "Defense Evasion"),
              Stage("c2_beacon", "Command and Control")]),
    Scenario("web_compromise", "web-facing server compromise",
             [Stage("web_exploit", "Initial Access"),
              Stage("webshell", "Persistence"),
              Stage("encoded_powershell", "Execution"),
              Stage("c2_beacon", "Command and Control")]),
]


def _scenario_finding(sc: Scenario, fired: list[tuple[Stage, dict[str, Any]]]) -> dict[str, Any]:
    """Compose the stages that fired into one kill-chain narrative finding. Cites the
    union of the fired stages' (positive) evidence, so it verifies on real queries."""
    steps = " -> ".join(f"{st.tactic} ({f['technique']})" for st, f in fired)
    eids = sorted({e for _, f in fired for e in (f.get("evidence_ids") or [])})
    n, total = len(fired), len(sc.stages)
    severity = "critical" if (n >= 3 or any(f["severity"] == "critical" for _, f in fired)) else "high"
    claim = (f"Potential {sc.name} scenario indicators: {steps}. "
             f"{n} of {total} stages matched; events are not correlated by host or time.")
    return {"claim": claim, "evidence_ids": eids, "mitre": "kill-chain", "technique": sc.name,
            "severity": severity, "detail": "", "role": "positive",
            "scenario": sc.sid, "stages_present": n, "stages_total": total}


def run_heuristic_hunt(hypothesis: str, client: MCPClient, ledger: EvidenceLedger,
                       on_event=lambda e: None) -> dict[str, Any]:
    """Deterministic SCAN. The hypothesis is NOT interpreted here: a no-LLM engine
    cannot understand natural language, and we never keyword-match it. Instead it
    scans the data for every known attack pattern and reports what it finds (plus the
    kill-chains they compose). Matching a free-text hypothesis is the LLM engine's job.
    """
    try:
        sources = client.call("list_log_types", {})
    except Exception as exc:
        sources = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    ev = ledger.record("list_log_types", {}, sources)
    on_event({"type": "tool_result", "tool": "list_log_types", "result": ev.result_summary})

    findings = []
    fired = {}
    errors = skipped = 0
    available = {x.get("index") for x in sources.get("log_types", [])} if _ok(sources) else set()
    for probe in PROBES:
        required_index = _LEGACY_INDEX.get(probe.pid)
        if available and required_index and required_index not in available:
            skipped += 1
            continue
        on_event({"type": "probe", "name": probe.name, "mitre": probe.mitre})
        try:
            finding, ok, absence = probe.run(client, ledger)
        except Exception as exc:
            errors += 1
            on_event({"type": "warning", "message": f"Probe {probe.pid} failed: {type(exc).__name__}"})
            continue
        if not ok:
            errors += 1
        if finding:
            fired[probe.pid] = finding
        item = finding or absence
        if item:
            item = dict(item, probe=probe.pid, addresses_hypothesis=False)
            findings.append(item)
            on_event({"type": "finding", "finding": item})

    # Detect raw Windows/Sysmon records by their mappings, and query each
    # matching source separately. Unknown fields are skipped, not called absent.
    mordor_runs = mordor_errors = mapping_errors = 0
    mordor_detected = set()
    mordor_probed = set()
    raw_sources = []
    for source in (sources.get("log_types", []) if _ok(sources) else []):
        index = source.get("index", "")
        if not (index.startswith("sherlock-logs-mordor_") or
                index == os.environ.get("SHERLOCK_LOG_SCOPE", "")):
            continue
        mapping = client.call("get_field_mapping", {"index": index})
        ledger.record("get_field_mapping", {"index": index}, mapping)
        if not _ok(mapping):
            mapping_errors += 1
            continue
        fields = mapping.get("fields", {})
        raw_sources.append(index)
        for pid, query, mitre, technique, severity, hit, _ in _MORDOR_SPECS:
            required = set(re.findall(r"([A-Za-z][A-Za-z0-9_]*):", query))
            if not required.issubset(fields):
                continue
            args = {"index": index, "query_string": query}
            try:
                response = client.call("count_logs", args)
            except Exception as exc:
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            ev = ledger.record("count_logs", args, response)
            mordor_runs += 1
            mordor_probed.add(technique)
            if not _ok(response):
                mordor_errors += 1
                continue
            if _matched(response) > 0:
                finding = _finding(f"{hit}: {_matched(response)} event(s) in {index}.",
                                   [ev.evidence_id], mitre, technique, severity)
                finding.update({"probe": f"mordor_{pid}", "addresses_hypothesis": False})
                findings.append(finding)
                mordor_detected.add(technique)
                on_event({"type": "finding", "finding": finding})

    for scenario in SCENARIOS:
        stages = [(stage, fired[stage.probe]) for stage in scenario.stages if stage.probe in fired]
        if len(stages) >= 2:
            item = _scenario_finding(scenario, stages)
            item["addresses_hypothesis"] = False
            findings.append(item)
            on_event({"type": "finding", "finding": item})

    verdict = "confirmed" if fired or mordor_detected else "inconclusive"
    coverage = {"mode": "scan", "probes_run": len(PROBES) - skipped + mordor_runs,
                "probes_skipped": skipped,
                "probes_ok": len(PROBES) - skipped - errors + mordor_runs - mordor_errors, "probe_errors": errors + mordor_errors, "mapping_errors": mapping_errors,
                "mordor_sources": raw_sources,
                "techniques_probed": sorted({p.technique for p in PROBES if not available or not _LEGACY_INDEX.get(p.pid) or _LEGACY_INDEX[p.pid] in available} | mordor_probed),
                "techniques_detected": sorted({p.technique for p in PROBES if p.pid in fired} | mordor_detected)}
    return {"verdict": verdict, "confidence": 0.6, "findings": findings,
            "coverage": coverage, "summary": "", "engine": "heuristic",
            "hypothesis_covered": False}
