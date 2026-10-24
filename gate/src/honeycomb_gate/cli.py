"""honeycomb-gate command line."""

import getpass
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import anyio
import typer

from honeycomb_gate import __version__
from honeycomb_gate.config import GateConfig, load_config
from honeycomb_gate.decoys import DecoyBook
from honeycomb_gate.events import LogCorruptError, query_events, verify_chain
from honeycomb_gate.front_door import serve_http
from honeycomb_gate.identity import MAX_TTL_S, Identities, Inventory, KeyRing, TokenError
from honeycomb_gate.incidents import Incident, IncidentStore, render_text
from honeycomb_gate.locking import StateCorruptError
from honeycomb_gate.notify import Notifier, load_dotenv
from honeycomb_gate.posture import assess
from honeycomb_gate.proxy import SEP, serve
from honeycomb_gate.redact import sanitize_name
from honeycomb_gate.registry import PinStore
from honeycomb_gate.runs import RunControl
from honeycomb_gate.tokens import KINDS, PlacementError, TokenRegistry
from honeycomb_gate.tokens import place as place_token

app = typer.Typer(help="honeycomb-gate: an immune system for AI agents.", no_args_is_help=True)
ConfigOpt = Annotated[Path, typer.Option("--config", help="Gate config YAML file.")]


def _fail(message: str, code: int = 1) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(code)


def _cfg(config: Path) -> GateConfig:
    try:
        return load_config(config)
    except Exception as exc:
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(2) from exc


def _serve(serve_fn: Callable[[GateConfig, Path | None], Awaitable[None]], config: Path) -> None:
    load_dotenv()
    try:
        anyio.run(serve_fn, _cfg(config), config)
    except* (StateCorruptError, LogCorruptError) as group:  # may arrive wrapped in a group
        typer.echo(f"Not starting: {group.exceptions[0]}", err=True)
        raise typer.Exit(1) from None


@app.command()
def run(config: ConfigOpt) -> None:
    """Serve the gate over stdio: point your MCP client at this command."""
    _serve(serve, config)


@app.command("serve")
def serve_cmd(config: ConfigOpt) -> None:
    """Serve the gate over HTTP: every request must carry a run token (see 'identity issue')."""
    _serve(serve_http, config)


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
        _fail(f"Nothing to approve for {name}. See 'honeycomb-gate tools list'.")
    if result == "stale":
        _fail(
            "The pending definition is not the one with that hash: it changed after you "
            "looked. Run 'tools show' again and review it.",
        )
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
        _fail("No index yet: start the gate once to create it.")
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
    _fail(f"BROKEN at line {report.first_break}: {report.reason}")


# -- honeytokens ------------------------------------------------------------------------------

tokens = typer.Typer(help="Create, list and revoke honeytokens (fake credentials).")
app.add_typer(tokens, name="tokens")


def _masked(value: str) -> str:
    return value[:6] + "..." + value[-4:]


@tokens.command("create")
def tokens_create(
    config: ConfigOpt,
    kind: Annotated[str, typer.Option(help=f"One of: {', '.join(KINDS)}.")],
    place: Annotated[Path, typer.Option(help="File or folder in the agent's workspace.")],
    allow_in_repo: Annotated[
        bool, typer.Option(help="Allow a path inside a git repository.")
    ] = False,
) -> None:
    """Make a fake credential and plant it where only a snooping agent would look."""
    cfg = _cfg(config)
    if kind not in KINDS:
        _fail(f"Unknown kind {kind!r}. Choose one of: {', '.join(KINDS)}.", 2)
    registry = TokenRegistry(cfg.tokens_path)
    token = registry.create(kind)
    try:
        written = place_token(token, place, allow_in_repo=allow_in_repo)
    except PlacementError as exc:
        registry.revoke(token.id)
        typer.echo(f"Not planted: {exc}", err=True)
        raise typer.Exit(1) from exc
    registry.add_placement(token.id, str(written))
    typer.echo(f"Planted {kind} honeytoken {token.id} in {written}")
    typer.echo("Any appearance of it in a tool call or result will pause the run.")


@tokens.command("list")
def tokens_list(config: ConfigOpt) -> None:
    """List honeytokens. Values are masked."""
    for t in TokenRegistry(_cfg(config).tokens_path).tokens():
        state = "revoked" if t.revoked else "active"
        typer.echo(f"{t.id}  {t.kind:<12} {state:<8} {_masked(t.value)}  {', '.join(t.placed)}")


@tokens.command("revoke")
def tokens_revoke(token_id: str, config: ConfigOpt) -> None:
    """Stop watching for a token (for example after removing it from the workspace)."""
    if not TokenRegistry(_cfg(config).tokens_path).revoke(token_id):
        _fail(f"Unknown token {token_id}.")
    typer.echo(f"Revoked {token_id}.")


# -- decoys, runs, incidents ---------------------------------------------------------------------

decoys = typer.Typer(help="Show the decoy tools chosen for this deployment.")
app.add_typer(decoys, name="decoys")


@decoys.command("list")
def decoys_list(config: ConfigOpt) -> None:
    """List this deployment's decoy tools (after the gate has run once)."""
    cfg = _cfg(config)
    if not cfg.decoys.count:
        typer.echo("Decoys are off. Set decoys.count in the config to turn them on.")
        return
    book = DecoyBook(cfg.decoys, list(cfg.upstreams), cfg.decoys_path)
    for name in book.full_names:
        typer.echo(name)


runs = typer.Typer(help="Paused runs and resuming them.")
app.add_typer(runs, name="runs")


@runs.command("list")
def runs_list(config: ConfigOpt) -> None:
    """Show runs that are paused and waiting for a person."""
    paused = RunControl(_cfg(config).runs_path).paused()
    if not paused:
        typer.echo("No paused runs.")
    for run_id, entry in paused.items():
        resume = "  (resume requested)" if "resume_requested_by" in entry else ""
        typer.echo(f"{run_id}  {entry['reason']}  {entry['tool']}  {entry['at']}{resume}")


@runs.command("resume")
def runs_resume(run_id: str, config: ConfigOpt) -> None:
    """Let a paused run continue. The old identity stays revoked; a new one is issued."""
    cfg = _cfg(config)
    control = RunControl(cfg.runs_path)
    result = control.request_resume(run_id, getpass.getuser())
    if result != "ok":
        _fail(f"Cannot resume {run_id}: {result}. See 'honeycomb-gate runs list'.")
    ids = _identities(cfg)
    old = ids.get(run_id)
    if old is None:
        typer.echo("Resume requested. The running gate issues a new identity on the next request.")
        return
    # A run that came in over HTTP holds a token, so it gets a new token instead.
    new_run, token = ids.issue(old["agent"], _scopes(cfg, old), resumed_from=run_id)
    control.take_resume(run_id, new_run)
    typer.echo(f"Resumed as {new_run}. Give the agent this token (valid 15 minutes):", err=True)
    typer.echo(token)


def _scopes(cfg: GateConfig, entry: dict[str, Any]) -> list[str]:
    """What the agent may do now: its current registration, else what the old token had."""
    registered = cfg.agents.get(entry["agent"])
    return list(registered.scopes) if registered else list(entry["scopes"])


def _identities(cfg: GateConfig) -> Identities:
    return Identities(cfg.identities_path, KeyRing(cfg.keys_path))


identity = typer.Typer(help="Run tokens: issue, renew, revoke, and rotate the signing key.")
app.add_typer(identity, name="identity")


@identity.command("issue")
def identity_issue(
    config: ConfigOpt,
    agent: Annotated[str, typer.Option(help="Agent id this token is for.")],
    ttl: Annotated[int, typer.Option(help=f"Seconds the token lives (at most {MAX_TTL_S}).")] = (
        MAX_TTL_S
    ),
) -> None:
    """Issue a run token. The token goes to stdout so a script can capture it."""
    cfg = _cfg(config)
    registered = cfg.agents.get(agent)
    if registered is None and cfg.mode == "strict":
        _fail(f"{agent} is not registered. Add it under 'agents:' in the config.")
    if registered is None:
        typer.echo(
            f"Note: {agent} is not registered, so it gets full scope (learning mode).", err=True
        )
    scopes = registered.scopes if registered else ["*"]
    try:
        run_id, token = _identities(cfg).issue(agent, scopes, ttl)
    except TokenError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"Run {run_id} for {agent}, scopes {', '.join(scopes)}.", err=True)
    typer.echo(token)


@identity.command("renew")
def identity_renew(run_id: str, config: ConfigOpt) -> None:
    """Print a fresh token for a run whose identity is still active."""
    try:
        cfg = _cfg(config)
        ids = _identities(cfg)
        entry = ids.get(run_id)
        typer.echo(ids.renew(run_id, scopes=_scopes(cfg, entry) if entry else None))
    except TokenError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@identity.command("revoke")
def identity_revoke(run_id: str, config: ConfigOpt) -> None:
    """Revoke a run's identity. Its tokens stop working on the next request."""
    if not _identities(_cfg(config)).revoke(run_id, f"revoked by {getpass.getuser()}"):
        _fail(f"{run_id} has no active identity.")
    typer.echo(f"Revoked {run_id}.")


@identity.command("list")
def identity_list(config: ConfigOpt) -> None:
    """List run identities, oldest first."""
    entries = _identities(_cfg(config)).all()
    for run_id, e in sorted(entries.items(), key=lambda kv: kv[1]["issued"]):
        until = datetime.fromtimestamp(e["expires"], UTC).isoformat(timespec="seconds")
        typer.echo(f"{run_id}  {e['status']:<8} {e['agent']}  until {until}")
    if not entries:
        typer.echo("No identities issued yet.")


@identity.command("rotate-key")
def identity_rotate_key(config: ConfigOpt) -> None:
    """Start signing with a new key. Old keys keep working until no token can use them."""
    keys = _identities(_cfg(config)).keys
    kid = keys.rotate()
    gone = keys.prune()
    typer.echo(f"Now signing with {kid}." + (f" Dropped {', '.join(gone)}." if gone else ""))


@app.command()
def posture(config: ConfigOpt) -> None:
    """Say which enforcement level is in place, what is only declared, and what is missing."""
    report = assess(_cfg(config))
    suffix = f", network {report.network}" if report.level >= 2 else ""
    typer.echo(f"Enforcement level: {report.title}{suffix}")
    for ok, text in report.checks:
        typer.echo(f"  [{'x' if ok else ' '}] {text}")
    typer.echo("To go further:")
    for step in report.next_steps:
        typer.echo(f"  - {step}")


agents = typer.Typer(help="The agents this gate knows about.")
app.add_typer(agents, name="agents")


@agents.command("list")
def agents_list(config: ConfigOpt) -> None:
    """Registered agents, plus any others the gate has seen."""
    cfg = _cfg(config)
    seen = Inventory(cfg.inventory_path).all()
    for name in sorted({*cfg.agents, *seen}):
        mark = "registered" if name in cfg.agents else "UNREGISTERED"
        info = seen.get(name)
        when = (
            datetime.fromtimestamp(info["last_seen"], UTC).isoformat(timespec="seconds")
            if info
            else "never seen"
        )
        runs_seen = info["runs"] if info else 0
        scopes = ", ".join(cfg.agents[name].scopes) if name in cfg.agents else "-"
        typer.echo(f"{sanitize_name(name)}  {mark}  runs {runs_seen}  last {when}  scopes {scopes}")
    if not cfg.agents and not seen:
        typer.echo("No agents registered or seen yet.")


incidents = typer.Typer(help="Incidents opened by the gate.")
app.add_typer(incidents, name="incidents")


@incidents.command("list")
def incidents_list(config: ConfigOpt) -> None:
    """List incidents, oldest first."""
    for i in IncidentStore(_cfg(config).incidents_dir).all():
        typer.echo(f"{i.id}  {i.state:<12} {i.severity:<8} {i.opened_at}  {sanitize_name(i.title)}")


@incidents.command("show")
def incidents_show(incident_id: str, config: ConfigOpt) -> None:
    """Print an incident as the notification message reads."""
    incident = IncidentStore(_cfg(config).incidents_dir).get(incident_id)
    if incident is None:
        _fail(f"Unknown incident {incident_id}.")
    typer.echo(render_text(incident))


@incidents.command("ack")
def incidents_ack(incident_id: str, config: ConfigOpt) -> None:
    """Acknowledge an incident: you have seen it and are looking at it."""
    if not IncidentStore(_cfg(config).incidents_dir).acknowledge(incident_id, getpass.getuser()):
        _fail(f"Unknown incident {incident_id}.")
    typer.echo(f"Acknowledged {incident_id}.")


notify = typer.Typer(help="Check the notification settings.")
app.add_typer(notify, name="notify")


@notify.command("test")
def notify_test(config: ConfigOpt) -> None:
    """Send a clearly labelled test message through every configured channel."""
    load_dotenv()
    cfg = _cfg(config)
    test = Incident(
        id="inc_test",
        severity="info",
        kind="test",
        title="Test message from honeycomb-gate",
        run_id="run_test",
        agent_id=cfg.agent_id,
        tool="-",
        opened_at="now",
        what="This is only a test of your notification settings. Nothing has happened.",
        confidence="Not applicable.",
        actions=["Nothing."],
        next_steps=["If you can read this, notifications work."],
    )
    results = anyio.run(Notifier(cfg.notify).send, test)
    if not results:
        _fail("No channel is configured (set notify.email or a webhook).")
    failed = False
    for r in results:
        typer.echo(f"{r.channel}: {'sent' if r.ok else 'FAILED (' + r.error + ')'}")
        failed = failed or not r.ok
    raise typer.Exit(1 if failed else 0)


if __name__ == "__main__":
    app()
