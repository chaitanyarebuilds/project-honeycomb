import json
import sys
from pathlib import Path

import pytest
import yaml
from mcp import Client
from mcp.client.stdio import StdioServerParameters

SAMPLE = str(Path(__file__).parent / "sample_server.py")


def _gate_params(tmp_path: Path) -> tuple[StdioServerParameters, Path]:
    log = tmp_path / "events.jsonl"
    cfg = tmp_path / "gate.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "event_log": str(log),
                "upstreams": {
                    "sample": {"transport": "stdio", "command": [sys.executable, SAMPLE]}
                },
            }
        )
    )
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "honeycomb_gate.cli", "run", "--config", str(cfg)]
    )
    return params, log


def _events(log: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in log.read_text().splitlines()]


async def test_tools_are_namespaced_and_calls_pass_through(tmp_path: Path) -> None:
    params, log = _gate_params(tmp_path)
    async with Client(params) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert names == {"sample__add", "sample__echo"}
        result = await client.call_tool("sample__add", {"a": 2, "b": 3})
        assert not result.is_error
        assert "5" in result.content[0].text  # type: ignore[union-attr]
    kinds = [e["kind"] for e in _events(log)]
    assert kinds[0] == "session.started"
    assert "tools.listed" in kinds
    assert "call.allowed" in kinds


async def test_unknown_tool_is_denied_and_logged(tmp_path: Path) -> None:
    params, log = _gate_params(tmp_path)
    async with Client(params) as client:
        result = await client.call_tool("nope__thing", {})
        assert result.is_error
    denied = [e for e in _events(log) if e["kind"] == "call.denied"]
    assert denied and denied[0]["reason"] == "unknown_tool"


def test_args_are_not_stored_raw(tmp_path: Path) -> None:
    from honeycomb_gate.events import EventLog, digest

    secret = {"api_key": "sk-test-NOT-REAL"}
    ev = EventLog(tmp_path / "e.jsonl")
    ev.emit("call.allowed", args_digest=digest(secret))
    assert "sk-test" not in (tmp_path / "e.jsonl").read_text()


@pytest.mark.parametrize("name", ["a__b", "x__y"])
def test_upstream_names_cannot_contain_separator(name: str, tmp_path: Path) -> None:
    from honeycomb_gate.config import load_config

    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"upstreams": {name: {"command": ["x"]}}}))
    with pytest.raises(ValueError):
        load_config(cfg)
