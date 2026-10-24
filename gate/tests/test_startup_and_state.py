"""The gate refuses to start on lost or tampered state, and says which file and what to do."""

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from helpers import write_config
from honeycomb_gate.cli import app
from honeycomb_gate.config import load_config
from honeycomb_gate.events import EventLog, LogCorruptError, query_events
from honeycomb_gate.locking import StateCorruptError
from honeycomb_gate.policy import PolicyConfig, PolicyEngine
from honeycomb_gate.proxy import check_state
from honeycomb_gate.registry import PinStore
from honeycomb_gate.runs import RunControl
from honeycomb_gate.tokens import PlacementError, TokenRegistry, place
from honeycomb_gate.walk import exceeds_depth, strings_of


def started(tmp_path: Path, **config: object) -> Path:
    """A gate state folder that has run before: a log, a sink and one pinned tool."""
    cfg_path = write_config(tmp_path, alert_sink=str(tmp_path / "sink.jsonl"), **config)
    cfg = load_config(cfg_path)
    log = EventLog(cfg.event_log_path, alert_sink=cfg.alert_sink)
    log.emit("tool.pinned", tool="sample__echo")
    log.emit("tool.definition_changed", severity="high", tool="sample__echo")
    log.close()
    PinStore(cfg.pins_path).check("sample", "echo", {"name": "echo"}, strict=False)
    return cfg_path


def test_a_fresh_start_and_a_healthy_restart_are_fine(tmp_path: Path) -> None:
    check_state(load_config(write_config(tmp_path)))  # nothing there yet
    again = tmp_path / "again"
    again.mkdir()
    check_state(load_config(started(again)))


def test_deleting_the_pin_file_does_not_quietly_trust_a_quarantined_tool(tmp_path: Path) -> None:
    cfg = load_config(started(tmp_path))
    cfg.pins_path.unlink()
    with pytest.raises(StateCorruptError, match="pins.json is missing"):
        check_state(cfg)


def test_an_edited_truncated_or_vanished_log_stops_the_gate(tmp_path: Path) -> None:
    cfg = load_config(started(tmp_path))
    rows = cfg.event_log_path.read_text().splitlines()
    cfg.event_log_path.write_text("\n".join(rows[:1]) + "\n")  # tail cut off
    with pytest.raises(StateCorruptError, match="integrity check"):
        check_state(cfg)
    cfg.event_log_path.unlink()  # the whole log removed, the sink still remembers
    with pytest.raises(StateCorruptError, match="integrity check"):
        check_state(cfg)


def test_a_missing_second_sink_stops_the_gate_with_a_way_out(tmp_path: Path) -> None:
    cfg = load_config(started(tmp_path))
    assert cfg.alert_sink is not None
    cfg.alert_sink.unlink()
    with pytest.raises(StateCorruptError, match="create an empty file"):
        check_state(cfg)
    cfg.alert_sink.write_text("")  # the documented way to say "I just turned the sink on"
    check_state(cfg)


def test_the_run_command_says_why_it_will_not_start(tmp_path: Path) -> None:
    cfg_path = started(tmp_path)
    load_config(cfg_path).pins_path.unlink()
    result = CliRunner().invoke(app, ["run", "--config", str(cfg_path)])
    assert result.exit_code == 1 and "Not starting" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("content", ["", "{not json", "[1, 2]", '"a string"', "\x00\x01"])
def test_a_damaged_state_file_gives_one_clear_error_naming_it(tmp_path: Path, content: str) -> None:
    for store, name in (
        (lambda p: PinStore(p).entries(), "pins.json"),
        (lambda p: RunControl(p).paused(), "runs.json"),
        (lambda p: TokenRegistry(p).tokens(), "tokens.json"),
    ):
        path = tmp_path / name
        path.write_text(content)
        with pytest.raises(StateCorruptError, match=name):
            store(path)


def test_deleting_the_event_log_but_not_its_index_does_not_crash_the_start(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "events.jsonl")
    log.emit("call.allowed")
    log.close()
    (tmp_path / "events.jsonl").unlink()
    EventLog(tmp_path / "events.jsonl").close()
    assert query_events(tmp_path / "events.sqlite3") == []


def test_a_token_is_found_however_deep_it_is_nested(tmp_path: Path) -> None:
    reg = TokenRegistry(tmp_path / "t.json")
    t = reg.create("api-key")
    for depth in (5, 11, 13, 40, 800):
        payload: object = t.value
        for _ in range(depth):
            payload = {"k": [payload]}
        assert reg.find(payload), depth
    assert strings_of({"a": [{"b": ("x", 3)}]}, numbers=True) == ["a", "b", "x", "3"]
    assert exceeds_depth([[[[1]]]], 3) and not exceeds_depth([[[1]]], 3)


def test_padding_cannot_hide_a_value_from_a_deny_regex() -> None:
    rule = {
        "id": "d",
        "match": {"tool": "a__t", "args": {"cmd": {"regex": "rm -rf"}}},
        "action": "deny",
    }
    e = PolicyEngine(PolicyConfig.model_validate({"rules": [rule]}))
    assert e.evaluate("a", "a__t", {"cmd": "rm -rf /"}).action == "deny"
    assert e.evaluate("a", "a__t", {"cmd": "A" * 20_000 + "rm -rf /"}).action == "deny"
    assert e.evaluate("a", "a__t", {"cmd": "ls -la"}).action == "allow"  # a normal command passes


def test_rule_globs_ignore_case() -> None:
    rule = {"id": "d", "match": {"tool": "*__delete*"}, "action": "deny"}
    e = PolicyEngine(PolicyConfig.model_validate({"rules": [rule]}))
    assert e.evaluate("s", "s__Delete_all", {}).action == "deny"
    assert e.evaluate("s", "s__read", {}).action == "allow"


@pytest.mark.parametrize(
    "decoys",
    [
        {"count": 2, "vocabulary": []},
        {"count": 3, "vocabulary": ["a_b", "c_d"]},
        {"count": 2, "vocabulary": ["same", "same"]},
        {"count": 1, "vocabulary": [""]},
        {"count": 1, "vocabulary": ["bad‮name"]},
        {"count": 1, "vocabulary": ["Has Spaces"]},
        {"count": 1, "placement": "nowhere"},
    ],
)
def test_bad_decoy_settings_are_caught_when_the_config_loads(tmp_path: Path, decoys: dict) -> None:  # type: ignore[type-arg]
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump({"decoys": decoys, "upstreams": {"a": {"command": ["x", "y"]}}}))
    with pytest.raises(ValidationError):
        load_config(cfg)


def test_a_state_dir_that_is_a_file_is_caught_at_load(tmp_path: Path) -> None:
    (tmp_path / "state").write_text("not a folder")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {"state_dir": str(tmp_path / "state"), "upstreams": {"a": {"command": ["x"]}}}
        )
    )
    with pytest.raises(ValidationError, match="is a file"):
        load_config(cfg)


def test_a_symlink_cannot_smuggle_a_honeytoken_into_a_git_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "target.env").write_text("")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "link.env").symlink_to(repo / "target.env")
    token = TokenRegistry(tmp_path / "t.json").create("api-key")
    with pytest.raises(PlacementError, match="never be committed"):
        place(token, ws / "link.env")
    assert (repo / "target.env").read_text() == ""


def test_an_unwritable_place_is_a_clean_error(tmp_path: Path) -> None:
    token = TokenRegistry(tmp_path / "t.json").create("api-key")
    blocker = tmp_path / "file"
    blocker.write_text("")
    with pytest.raises(PlacementError, match="could not write"):
        place(token, blocker / "inside" / ".env")  # a "folder" that is really a file


def test_a_json_state_file_is_not_left_half_written(tmp_path: Path) -> None:
    runs = RunControl(tmp_path / "runs.json")
    runs.pause("run_a", "decoy.tripped", "t")
    assert json.loads((tmp_path / "runs.json").read_text())["run_a"]["status"] == "paused"
    assert not list(tmp_path.glob("*.tmp"))


def test_every_damaged_state_file_stops_the_gate_with_one_clear_message(tmp_path: Path) -> None:
    for name in ("decoys.json", "tokens.json", "runs.json", "pins.json"):
        folder = tmp_path / name.split(".")[0]
        folder.mkdir()
        cfg_path = write_config(folder, decoys={"count": 1, "vocabulary": ["a_b"]})
        (folder / "state").mkdir(exist_ok=True)
        (folder / "state" / name).write_text("{broken")
        result = CliRunner().invoke(app, ["run", "--config", str(cfg_path)])
        assert result.exit_code == 1, name
        assert "Not starting" in result.output and name in result.output, name
        assert "Traceback" not in result.output and "ExceptionGroup" not in result.output


def test_a_second_gate_gets_the_lock_message_not_a_corruption_report(tmp_path: Path) -> None:
    cfg = load_config(write_config(tmp_path))
    first = EventLog(cfg.event_log_path)
    first.emit("call.allowed")
    with pytest.raises(LogCorruptError, match="already writing"):
        check_state(cfg)
    first.close()


def test_a_baseline_file_of_the_wrong_shape_stops_the_gate_and_the_command(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "baselines.json").write_text('{"agents": {"a": {"runs": 9}}}')
    shown = CliRunner().invoke(app, ["baseline", "show", "--config", str(cfg)])
    assert shown.exit_code == 1 and "baseline file" in (shown.stderr or shown.output)
    with pytest.raises(StateCorruptError):
        check_state(load_config(cfg))
