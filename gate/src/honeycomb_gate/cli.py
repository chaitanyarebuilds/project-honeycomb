"""honeycomb-gate command line (M0: ``run`` and ``version``)."""

import json
from pathlib import Path
from typing import Annotated

import anyio
import typer

from honeycomb_gate import __version__
from honeycomb_gate.config import load_config
from honeycomb_gate.proxy import serve

app = typer.Typer(help="honeycomb-gate: an immune system for AI agents.", no_args_is_help=True)


@app.command()
def run(
    config: Annotated[Path, typer.Option("--config", help="Policy/config YAML file.")],
) -> None:
    """Serve the gate over stdio: point your MCP client at this command."""
    anyio.run(serve, load_config(config))


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


events = typer.Typer(help="Inspect the event log.")
app.add_typer(events, name="events")


@events.command()
def tail(
    path: Annotated[Path, typer.Option("--file")] = Path(".honeycomb/events.jsonl"),
    n: Annotated[int, typer.Option("-n")] = 20,
) -> None:
    """Show the last N events as one readable line each."""
    for line in path.read_text().splitlines()[-n:]:
        e = json.loads(line)
        typer.echo(f"{e['ts']} {e['severity']:<8} {e['kind']} {e.get('tool', '')}".rstrip())


if __name__ == "__main__":
    app()
