"""honeycomb-gate command line."""

import getpass
import json
from pathlib import Path
from typing import Annotated

import anyio
import typer

from honeycomb_gate import __version__
from honeycomb_gate.config import GateConfig, load_config
from honeycomb_gate.events import query_events, verify_chain
from honeycomb_gate.proxy import SEP, serve
from honeycomb_gate.redact import sanitize_name
from honeycomb_gate.registry import PinStore

app = typer.Typer(help="honeycomb-gate: an immune system for AI agents.", no_args_is_help=True)
ConfigOpt = Annotated[Path, typer.Option("--config", help="Gate config YAML file.")]


def _cfg(config: Path) -> GateConfig:
    try:
        return load_config(config)
    except Exception as exc:
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(2) from exc


@app.command()
def run(config: ConfigOpt) -> None:
    """Serve the gate over stdio: point your MCP client at this command."""
    anyio.run(serve, _cfg(config))


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


policy = typer.Typer(help="Check policy files.")
app.add_typer(policy, name="policy")


@policy.command("check")
def policy_check(config: ConfigOpt) -> None:
    """Validate a config and policy file without starting the gate."""
    cfg = _cfg(config)
    typer.echo(f"OK: mode={cfg.mode}, {len(cfg.rules)} rule(s), {len(cfg.upstreams)} upstream(s)")


tools = typer.Typer(help="Inspect and approve pinned tool definitions.")
app.add_typer(tools, name="tools")


def _short(h: str | None) -> str:
    return (h or "-").removeprefix("sha256:")[:12]


@tools.command("list")
def tools_list(config: ConfigOpt) -> None:
    """Show every known tool, its status and its hashes."""
    entries = PinStore(_cfg(config).pins_path).entries()
    if not entries:
        typer.echo("No tools seen yet. Start the gate and list tools from a client.")
    for upstream, items in sorted(entries.items()):
        for tool, entry in sorted(items.items()):
            pending = entry.get("pending_hash")
            note = f"  pending={_short(pending)}" if pending else ""
            typer.echo(
                f"{entry['status']:<12} {sanitize_name(upstream + SEP + tool):<40} "
                f"approved={_short(entry.get('hash'))}{note}"
            )


@tools.command("show")
def tools_show(name: str, config: ConfigOpt) -> None:
    """Show what changed in a quarantined tool (approved definition versus pending)."""
    upstream, _, tool = name.partition(SEP)
    diff = PinStore(_cfg(config).pins_path).diff(upstream, tool)
    typer.echo(diff if diff is not None else "Nothing pending for that tool.")


@tools.command("approve")
def tools_approve(
    name: str,
    config: ConfigOpt,
    hash: Annotated[str, typer.Option("--hash", help="Pending hash from 'tools list'.")],
) -> None:
    """Approve a pending definition. You must pass the hash you reviewed with 'tools show'."""
    upstream, _, tool = name.partition(SEP)
    result = PinStore(_cfg(config).pins_path).approve(
        upstream, tool, approver=getpass.getuser(), expected_hash=hash
    )
    if result == "unknown":
        typer.echo(f"Nothing to approve for {name}. See 'honeycomb-gate tools list'.", err=True)
        raise typer.Exit(1)
    if result == "stale":
        typer.echo(
            "The pending definition is not the one with that hash: it changed after you "
            "looked. Run 'tools show' again and review it.",
            err=True,
        )
        raise typer.Exit(1)
    typer.echo(f"Approved {name}. The running gate applies this on its next check.")


events = typer.Typer(help="Inspect the event log.")
app.add_typer(events, name="events")


def _line(e: dict[str, object]) -> str:
    tool = sanitize_name(e.get("tool") or "")
    return f"{e['ts']} {e['severity']:<8} {sanitize_name(e['kind']):<28} {tool}".rstrip()


@events.command()
def tail(config: ConfigOpt, n: Annotated[int, typer.Option("-n")] = 20) -> None:
    """Show the last N events, one line each."""
    path = _cfg(config).event_log_path
    if not path.exists():
        typer.echo("No events yet.")
        return
    for line in path.read_text().splitlines()[-n:]:
        typer.echo(_line(json.loads(line)))


@events.command()
def query(
    config: ConfigOpt,
    kind: Annotated[str | None, typer.Option(help="Kind, '*' wildcards allowed.")] = None,
    severity: Annotated[str | None, typer.Option(help="Minimum severity.")] = None,
    run: Annotated[str | None, typer.Option(help="Run id.")] = None,
    since: Annotated[str | None, typer.Option(help="ISO timestamp.")] = None,
    limit: int = 50,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Search events through the SQLite index."""
    db = _cfg(config).event_log_path.with_suffix(".sqlite3")
    if not db.exists():
        typer.echo("No index yet: start the gate once to create it.", err=True)
        raise typer.Exit(1)
    for e in query_events(
        db, kind=kind, min_severity=severity, run_id=run, since=since, limit=limit
    ):
        typer.echo(json.dumps(e) if as_json else _line(e))


@events.command()
def verify(config: ConfigOpt) -> None:
    """Check the hash chain (and the second sink's checkpoints). Exit 1 if tampered."""
    cfg = _cfg(config)
    report = verify_chain(cfg.event_log_path, cfg.alert_sink)
    if report.ok:
        typer.echo(
            f"OK: {report.events} events, chain intact." if report.events else "No events yet."
        )
        return
    typer.echo(f"BROKEN at line {report.first_break}: {report.reason}", err=True)
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
