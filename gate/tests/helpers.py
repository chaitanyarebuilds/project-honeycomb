import json
import sys
from pathlib import Path
from typing import Any

import yaml
from mcp.client.stdio import StdioServerParameters
from typer.testing import CliRunner

from honeycomb_gate.cli import app

SAMPLE = str(Path(__file__).parent / "sample_server.py")


def write_config(tmp_path: Path, **extra: Any) -> Path:
    cfg = {
        "schema_version": 1,
        "state_dir": str(tmp_path / "state"),
        "upstreams": {"sample": {"transport": "stdio", "command": [sys.executable, SAMPLE]}},
        **extra,
    }
    path = tmp_path / "gate.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


def gate_params(cfg: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable, args=["-m", "honeycomb_gate.cli", "run", "--config", str(cfg)]
    )


def read_log(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "state" / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def cli(*args: str) -> tuple[int, str, str]:
    result = CliRunner().invoke(app, list(args))
    return result.exit_code, result.stdout.strip(), result.stderr
