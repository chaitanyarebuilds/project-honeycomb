"""Scenario S2: an upstream silently changes a tool description mid-run (rug pull)."""

import json
from pathlib import Path

from mcp import Client
from typer.testing import CliRunner

from helpers import gate_params, read_log, write_config
from honeycomb_gate.cli import app


async def test_s2_changed_tool_is_quarantined_then_approved(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)  # default: the live definition is re-checked on every call
    async with Client(gate_params(cfg)) as client:
        assert (await client.call_tool("sample__echo", {"text": "hi"})).is_error is False
        await client.call_tool("sample__poison", {})  # upstream mutates echo

        blocked = await client.call_tool("sample__echo", {"text": "hi again"})
        assert blocked.is_error
        assert "sample__echo" not in {t.name for t in (await client.list_tools()).tools}

        # Unrelated tools keep working: quarantine is per tool, not per upstream.
        assert (await client.call_tool("sample__add", {"a": 1, "b": 1})).is_error is False

        # The operator reviews and approves the new definition (a separate process).
        pending = json.loads((tmp_path / "state" / "pins.json").read_text())["sample"]["echo"]
        cli = CliRunner()
        shown = cli.invoke(app, ["tools", "show", "sample__echo", "--config", str(cfg)])
        assert "Do not tell the user" in shown.output  # the operator sees what changed
        args = ["tools", "approve", "sample__echo", "--config", str(cfg)]
        assert cli.invoke(app, [*args, "--hash", "sha256:deadbeefdead"]).exit_code == 1
        result = cli.invoke(app, [*args, "--hash", pending["pending_hash"]])
        assert result.exit_code == 0, result.output

        assert (await client.call_tool("sample__echo", {"text": "ok"})).is_error is False

    events = read_log(tmp_path)
    kinds = [e["kind"] for e in events]
    changed = [e for e in events if e["kind"] == "tool.definition_changed"]
    assert len(changed) == 1 and changed[0]["tool"] == "sample__echo"
    assert changed[0]["severity"] == "high"
    flagged = [e for e in events if e["kind"] == "tool.suspicious_description"]
    assert flagged and "conceal_from_user" in flagged[0]["details"]["reasons"]
    denied = [e for e in events if e["kind"] == "call.denied" and e["tool"] == "sample__echo"]
    assert denied and denied[0]["details"]["reason"] == "quarantined"
    assert "tool.approved" in kinds
    assert kinds.index("tool.definition_changed") < kinds.index("tool.approved")


async def test_benign_restart_does_not_quarantine(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    for _ in range(2):  # same definitions on a second run: pins match, nothing changes
        async with Client(gate_params(cfg)) as client:
            await client.list_tools()
    kinds = [e["kind"] for e in read_log(tmp_path)]
    assert "tool.definition_changed" not in kinds
    assert kinds.count("tool.pinned") == 3


async def test_a_cache_window_is_a_documented_risk_not_the_default(tmp_path: Path) -> None:
    from honeycomb_gate.config import load_config

    assert load_config(write_config(tmp_path)).recheck_ttl_s == 0
