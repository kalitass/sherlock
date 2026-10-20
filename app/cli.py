"""Sherlock command-line interface.

  uv run sherlock seed                 # generate + agentically ingest 3 log types
  uv run sherlock ingest <path>        # ingest one file via auto-schema (pull)
  uv run sherlock hunt "<hypothesis>"  # run a threat hunt, print the report
  uv run sherlock experiment "<hyp>"   # run the same hunt twice and diff
  uv run sherlock status               # cluster + index + schema overview
  uv run sherlock schemas              # list registered parsing schemas
  uv run sherlock mcp                  # run the MCP server (stdio)
  uv run sherlock dashboard            # run the web dashboard

(Defined as the `sherlock` script via pyproject / uv, and runnable as
 `uv run python -m cli ...`.)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


def _seed(args) -> None:
    from datasets import generate
    from core.es import ensure_state_indices, wait_until_ready
    from components.ingestion.ingest_core import ingest_file
    from core.settings import settings

    if not wait_until_ready(90):
        console.print("[red]Elasticsearch is not reachable. Run `make up` first.[/red]")
        sys.exit(1)
    ensure_state_indices()
    console.print("[bold]Generating datasets…[/bold]")
    generate.main()
    gen = Path(generate.__file__).resolve().parent / "generated"
    use_llm = not args.no_llm
    table = Table(title="Agentic ingestion (auto-schema)")
    for col in ("file", "log_type", "indexed", "failures", "schema by", "parse rate", "reused"):
        table.add_column(col)
    for f in ["windows_security.json", "sysmon.json", "web_access.log"]:
        s = ingest_file(gen / f, mode="pull", use_llm=use_llm)
        table.add_row(f, s["log_type"], str(s["count_indexed"]), str(s["failures"]),
                      str(s["created_by"]), str(s["parse_rate"]), str(s["schema_reused"]))
    console.print(table)
    console.print(f"[green]Seed complete.[/green] Drop dir for pull ingestion: {settings.drop_dir}")


def _siem(args) -> None:
    """Onboard the same incident exported in the seven famous SIEM schemas (SE6014
    Week 2: CEF, LEEF, CIM, ECS, OCSF, ASIM, UDM) and normalise them all onto one
    canonical field set — "one event, seven spellings; normalise first"."""
    from datasets import siem_samples
    from core.es import ensure_state_indices, wait_until_ready
    from components.ingestion.ingest_core import ingest_file

    if not wait_until_ready(90):
        console.print("[red]Elasticsearch is not reachable. Run `make up` first.[/red]")
        sys.exit(1)
    ensure_state_indices()
    console.print("[bold]Generating the incident in all seven SIEM schemas…[/bold]\n")
    siem_samples.main()

    table = Table(title="Cross-schema onboarding + normalisation (SE6014 Week 2)")
    for col in ("file", "side", "schema", "log_type", "indexed", "parse rate", "drift"):
        table.add_column(col)
    files = [("cef.log", "producer", "CEF (ArcSight)"), ("leef.log", "producer", "LEEF (QRadar)"),
             ("cim.json", "consumer", "CIM (Splunk)"), ("ecs.json", "consumer", "ECS (Elastic)"),
             ("ocsf.json", "consumer", "OCSF"), ("asim.json", "consumer", "ASIM (Sentinel)"),
             ("udm.json", "consumer", "UDM (Google)")]
    for fname, side, label in files:
        s = ingest_file(siem_samples.OUT / fname, mode="pull", use_llm=False)
        ok = "[green]{}[/green]" if s["ok"] else "[red]{}[/red]"
        drift = (s.get("drift") or {}).get("status", "-")
        table.add_row(fname, side, label, s["log_type"], str(s["count_indexed"]),
                      ok.format(s.get("parse_rate")), drift)
    console.print(table)
    console.print("\n[bold]Normalise first:[/bold] one query now fires across every schema, e.g.")
    console.print("  [dim]uv run python -m cli hunt \"brute force against the administrator account "
                  "from an external IP\"[/dim]")
    console.print("  [dim]# each schema's index carries canonical n_user / n_src_ip / n_event_id / "
                  "n_action fields[/dim]")


def _scenario(args) -> None:
    """Load extra test scenarios (authored in the canonical/normalised schema)."""
    from datasets import scenarios as sc
    from core.es import ensure_state_indices, wait_until_ready
    from components.ingestion.ingest_core import ingest_records

    names = list(sc.SCENARIOS) if args.name in (None, "all") else [args.name]
    if args.name and args.name not in sc.SCENARIOS and args.name != "all":
        console.print(f"[red]unknown scenario '{args.name}'.[/red] Available: {list(sc.SCENARIOS)}")
        sys.exit(1)
    if not wait_until_ready(90):
        console.print("[red]Elasticsearch is not reachable. Run `make up` first.[/red]")
        sys.exit(1)
    ensure_state_indices()

    table = Table(title="Test scenarios (canonical schema)")
    for col in ("scenario", "host", "events", "index", "test hypothesis → expected"):
        table.add_column(col, overflow="fold")
    for name in names:
        meta = sc.SCENARIOS[name]
        events = sc.build(name)
        s = ingest_records(f"scn_{name}", events, source=f"scenario:{name}", mode="pull", use_llm=False)
        table.add_row(name, meta["host"], str(s["count_indexed"]), s["index"],
                      f"\"{meta['hypothesis']}\"\n→ {meta['expected']}")
    console.print(table)
    console.print("\nHunt a scenario (LLM engine recommended; benign also works deterministically):")
    console.print("  [dim]SHERLOCK_LLM_PROVIDER=deepseek uv run python -m cli hunt \"<the hypothesis above>\"[/dim]")


def _ingest(args) -> None:
    from components.ingestion.ingest_core import ingest_file
    s = ingest_file(Path(args.path), mode=args.mode, use_llm=not args.no_llm)
    console.print(s)


def _hunt(args) -> None:
    from core.pipeline import run_hunt

    def on_event(e):
        t = e.get("type")
        if t == "start":
            console.print(f"[bold cyan]▶ Hunt {e['hunt_id']}[/bold cyan] engine=[yellow]{e['engine']}[/yellow]")
        elif t == "mcp":
            console.print(f"  [dim]MCP backend={e['backend']} tools={len(e['tools'])}[/dim]")
        elif t == "probe":
            console.print(f"  [dim]• probe: {e['name']} ({e['mitre']})[/dim]")
        elif t == "tool_call":
            console.print(f"  [dim]→ {e['tool']} {e.get('summary','')}[/dim]")
        elif t == "finding":
            f = e["finding"]
            console.print(f"    [red]⚑ {f['severity'].upper()}[/red] {f['claim'][:90]}")
        elif t == "verdict":
            console.print(f"[bold]VERDICT: {e['verdict']}[/bold] "
                          f"(conf {e['confidence']}, integrity {e['verification_rate']:.0%})")

    use_llm = True if args.llm else (False if args.no_llm else None)
    bundle = run_hunt(args.hypothesis, run_label=args.run_label, use_llm=use_llm,
                      on_event=on_event, mcp_backend=args.backend)
    console.rule("Report")
    console.print(bundle["report_md"])
    console.print(f"\n[green]Report saved under reports/ as {bundle['meta']['hunt_id']}_"
                  f"{bundle['meta']['run_label']}.md[/green]")


def _experiment(args) -> None:
    from experiment.run_twice import run_experiment
    run_experiment(args.hypothesis, use_llm=(None if not args.no_llm else False))


def _status(args) -> None:
    from core.es import get_client, wait_until_ready
    from core.settings import LOG_INDEX_PREFIX, SCHEMA_INDEX, HUNT_INDEX
    if not wait_until_ready(20):
        console.print("[red]ES not reachable[/red]"); return
    es = get_client()
    h = es.cluster.health()
    console.print(f"cluster [bold]{h['status']}[/bold] nodes={h['number_of_nodes']}")
    t = Table(title="Indices")
    t.add_column("index"); t.add_column("docs", justify="right")
    for idx in sorted(es.indices.get(index=f"{LOG_INDEX_PREFIX}*", ignore_unavailable=True).keys()):
        t.add_row(idx, str(es.count(index=idx)["count"]))
    for idx in (SCHEMA_INDEX, HUNT_INDEX):
        if es.indices.exists(index=idx):
            t.add_row(idx, str(es.count(index=idx)["count"]))
    console.print(t)


def _sigma(args) -> None:
    from pathlib import Path
    from components.detection.sigma_import import run_demo
    paths = args.paths or sorted(str(p) for p in Path("components/detection/sigma_samples").glob("*.yml"))
    if not paths:
        console.print("[red]no Sigma rule files found[/red]")
        return
    console.print(f"[bold]Migrating {len(paths)} Sigma rule(s) -> canonical n_* detections[/bold]")
    run_demo(paths, use_llm=args.llm)


def _schemas(args) -> None:
    from components.ingestion import schema_registry as reg
    t = Table(title="Registered schemas")
    for c in ("name", "log_type", "v", "parser", "by", "rate", "fields"):
        t.add_column(c)
    for s in reg.list_schemas():
        val = s.get("validation", {})
        t.add_row(s["name"], s["log_type"], str(s["version"]), s.get("parser", {}).get("kind", "?"),
                  str(s.get("created_by")), str(val.get("rate")), str(len(s.get("field_map", {}))))
    console.print(t)


def _providers(args) -> None:
    from core.providers import list_providers
    from core.llm import LLMClient
    active = LLMClient()
    t = Table(title="Supported LLM providers (bring-your-own-model)")
    for c in ("provider", "engine", "default model", "endpoint", "ready"):
        t.add_column(c)
    for p in list_providers():
        ready = "[green]yes[/green]" if p["ready"] else "[dim]no key[/dim]"
        t.add_row(p["provider"], p["engine"], p["model"], p["endpoint"], ready)
    console.print(t)
    r = active._r
    status = "[green]available[/green]" if active.available() else "[yellow]no key → deterministic engine[/yellow]"
    console.print(f"\nActive: [bold]{active.provider}[/bold] · engine [bold]{r.engine}[/bold] · "
                  f"model [bold]{r.route or active.model}[/bold] · {status}")
    console.print(f"[dim]{r.note or 'ready'}[/dim]")
    console.print("[dim]Switch provider with SHERLOCK_LLM_PROVIDER=<provider>; force the loop "
                  "with SHERLOCK_LLM_ENGINE=litellm|native. No code change.[/dim]")


def _mcp(args) -> None:
    from core.mcp.server import main
    main()


def _dashboard(args) -> None:
    import uvicorn
    from core.settings import settings
    uvicorn.run("app.dashboard.app:app", host="0.0.0.0", port=settings.dashboard_port, log_level="info")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sherlock", description="Agentic threat hunting on ELK")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("seed", help="generate + ingest 3 log types")
    sp.add_argument("--no-llm", action="store_true", help="use deterministic schema detection")
    sp.set_defaults(func=_seed)

    ip = sub.add_parser("ingest", help="ingest one file via auto-schema")
    ip.add_argument("path"); ip.add_argument("--mode", default="pull")
    ip.add_argument("--no-llm", action="store_true"); ip.set_defaults(func=_ingest)

    siem = sub.add_parser("siem", help="onboard the incident from 7 SIEM schemas (CEF/LEEF/CIM/ECS/OCSF/ASIM/UDM)")
    siem.add_argument("--no-llm", action="store_true")
    siem.set_defaults(func=_siem)

    sg = sub.add_parser("sigma", help="migrate Sigma detection rules into canonical n_* detections")
    sg.add_argument("paths", nargs="*", help="Sigma .yml files (default: components/detection/sigma_samples/*)")
    sg.add_argument("--llm", action="store_true", help="use the LLM to map unknown fields")
    sg.set_defaults(func=_sigma)

    scn = sub.add_parser("scenario", help="load extra test scenarios (benign / password-spray / data-exfil)")
    scn.add_argument("name", nargs="?", default="all", help="scenario name, or 'all'")
    scn.set_defaults(func=_scenario)

    hp = sub.add_parser("hunt", help="run a threat hunt")
    hp.add_argument("hypothesis")
    hp.add_argument("--run-label", default="run-1")
    hp.add_argument("--llm", action="store_true", help="force LLM engine")
    hp.add_argument("--no-llm", action="store_true", help="force deterministic engine")
    hp.add_argument("--backend", default=None, help="mcp backend: stdio|direct")
    hp.set_defaults(func=_hunt)

    ep = sub.add_parser("experiment", help="run the same hunt twice and diff")
    ep.add_argument("hypothesis"); ep.add_argument("--no-llm", action="store_true")
    ep.set_defaults(func=_experiment)

    sub.add_parser("status", help="cluster/index overview").set_defaults(func=_status)
    sub.add_parser("schemas", help="list schemas").set_defaults(func=_schemas)
    sub.add_parser("providers", help="list supported LLM providers + readiness").set_defaults(func=_providers)
    sub.add_parser("mcp", help="run MCP server (stdio)").set_defaults(func=_mcp)
    sub.add_parser("dashboard", help="run web dashboard").set_defaults(func=_dashboard)
    return p


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
