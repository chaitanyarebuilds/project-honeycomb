import json
from pathlib import Path

import pytest

from honeycomb_gate.events import EventLog, LogCorruptError, query_events, verify_chain
from honeycomb_gate.redact import REDACTED, redact


def make_log(tmp_path: Path, n: int = 5, **kw: object) -> EventLog:
    log = EventLog(tmp_path / "events.jsonl", **kw)  # type: ignore[arg-type]
    for i in range(n):
        log.emit("call.allowed", tool=f"t{i}", severity="info")
    return log


def lines(tmp_path: Path) -> list[str]:
    return (tmp_path / "events.jsonl").read_text().splitlines()


def test_intact_chain_verifies_and_survives_restart(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    log.close()
    again = EventLog(tmp_path / "events.jsonl")  # a new run continues the same chain
    again.emit("session.started")
    report = verify_chain(tmp_path / "events.jsonl")
    assert report.ok and report.events == 6


def test_edited_line_is_detected(tmp_path: Path) -> None:
    make_log(tmp_path).close()
    rows = lines(tmp_path)
    e = json.loads(rows[2])
    e["tool"] = "innocent"
    rows[2] = json.dumps(e)
    (tmp_path / "events.jsonl").write_text("\n".join(rows) + "\n")
    report = verify_chain(tmp_path / "events.jsonl")
    assert (report.ok, report.first_break) == (False, 3)


def test_deleted_and_reordered_lines_are_detected(tmp_path: Path) -> None:
    make_log(tmp_path).close()
    rows = lines(tmp_path)
    (tmp_path / "events.jsonl").write_text("\n".join(rows[:2] + rows[3:]) + "\n")
    assert verify_chain(tmp_path / "events.jsonl").first_break == 3
    (tmp_path / "events.jsonl").write_text("\n".join([rows[1], rows[0], *rows[2:]]) + "\n")
    assert not verify_chain(tmp_path / "events.jsonl").ok


def test_truncation_is_caught_by_the_second_sink(tmp_path: Path) -> None:
    sink = tmp_path / "sink.jsonl"
    log = make_log(tmp_path, n=3, alert_sink=sink)
    log.emit("decoy.tripped", severity="critical")
    for _ in range(5):
        log.emit("call.allowed")  # low-severity events after the last high one
    log.close()
    rows = lines(tmp_path)
    (tmp_path / "events.jsonl").write_text("\n".join(rows[:4]) + "\n")  # attacker drops the tail
    assert verify_chain(tmp_path / "events.jsonl").ok  # the chain alone cannot tell
    report = verify_chain(tmp_path / "events.jsonl", sink)
    assert not report.ok and "shorter" in report.reason


def test_missing_evidence_does_not_verify(tmp_path: Path) -> None:
    sink = tmp_path / "sink.jsonl"
    make_log(tmp_path, n=3, alert_sink=sink).close()
    log_path = tmp_path / "events.jsonl"
    assert verify_chain(log_path, sink).ok
    sink.unlink()  # attacker removes the second sink
    assert not verify_chain(log_path, sink).ok
    sink.write_text("")  # a fresh empty sink cannot vouch for anything, but is not "missing"
    make_log(tmp_path / "other", n=2, alert_sink=tmp_path / "other" / "s.jsonl").close()
    other = tmp_path / "other"
    (other / "events.jsonl").unlink()  # attacker removes the main log instead
    report = verify_chain(other / "events.jsonl", other / "s.jsonl")
    assert not report.ok and "missing" in report.reason


def test_sink_gets_full_copies_of_high_and_critical_events_only(tmp_path: Path) -> None:
    sink = tmp_path / "sink.jsonl"
    log = EventLog(tmp_path / "events.jsonl", alert_sink=sink)
    log.emit("call.allowed")
    log.emit("tool.suspicious_description", severity="medium")
    log.emit("tool.definition_changed", severity="high")
    rows = [json.loads(r) for r in sink.read_text().splitlines()]
    copied = [r["event"]["kind"] for r in rows if r["type"] == "event"]
    assert copied == ["tool.definition_changed"]
    assert [r["count"] for r in rows if r["type"] == "checkpoint"] == [1, 2, 3]


def test_a_second_writer_is_refused_instead_of_forking_the_chain(tmp_path: Path) -> None:
    first = EventLog(tmp_path / "events.jsonl")
    with pytest.raises(LogCorruptError, match="already writing"):
        EventLog(tmp_path / "events.jsonl")
    first.close()
    EventLog(tmp_path / "events.jsonl").close()  # fine once the first is closed


def test_a_torn_last_line_stops_the_gate_with_a_clear_message(tmp_path: Path) -> None:
    make_log(tmp_path, n=2).close()
    with (tmp_path / "events.jsonl").open("a") as f:
        f.write('{"schema_version": 1, "kind": "call.allo')  # crash mid-write
    with pytest.raises(LogCorruptError, match="damaged"):
        EventLog(tmp_path / "events.jsonl")


def test_agent_chosen_names_cannot_forge_lines_or_bloat_the_log(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "events.jsonl")
    nasty = "evil\n2026-01-01T00:00:00Z info session.ended\x1b[2J" + "A" * 100_000
    event = log.emit("call.denied", tool=nasty, upstream="u\r\nforged")
    log.close()
    raw = (tmp_path / "events.jsonl").read_text()
    assert len(raw.splitlines()) == 1 and len(raw) < 2000
    assert "\x1b" not in event["tool"] and "\n" not in event["tool"]


def test_state_files_are_private_to_the_owner(tmp_path: Path) -> None:
    sink = tmp_path / "sink.jsonl"
    make_log(tmp_path, n=1, alert_sink=sink).close()
    for f in (tmp_path / "events.jsonl", sink):
        assert (f.stat().st_mode & 0o077) == 0


def test_query_filters_by_kind_severity_and_run(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "events.jsonl", run_id="run_a")
    log.emit("call.allowed")
    log.emit("call.denied", severity="low")
    log.emit("decoy.tripped", severity="critical")
    log.close()
    db = tmp_path / "events.sqlite3"
    assert [e["kind"] for e in query_events(db, kind="call.*")] == ["call.allowed", "call.denied"]
    assert [e["kind"] for e in query_events(db, min_severity="high")] == ["decoy.tripped"]
    assert len(query_events(db, run_id="run_a")) == 3 and not query_events(db, run_id="run_b")


def test_index_is_rebuilt_from_the_jsonl_if_missing(tmp_path: Path) -> None:
    make_log(tmp_path).close()
    (tmp_path / "events.sqlite3").unlink()
    EventLog(tmp_path / "events.jsonl").close()
    assert len(query_events(tmp_path / "events.sqlite3")) == 5


def test_secrets_are_redacted_but_ordinary_values_are_not() -> None:
    out = redact(
        {
            "password": "hunter2",
            "headers": {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz"},
            "url": "postgres://admin:s3cret@db.internal/app",
            "note": "use key sk-live-abcdefghijklmnop1234",
            "items": ["AKIAABCDEFGHIJKLMNOP", "plain"],
        }
    )
    assert out["password"] == REDACTED and out["headers"]["Authorization"] == REDACTED
    assert "s3cret" not in out["url"] and "sk-live" not in out["note"]
    assert out["items"] == [REDACTED, "plain"]
    benign = {"tokens_used": 12, "author": "Ada", "text": "the secret garden", "id": "sk-8", "n": 3}
    assert redact(benign) == benign


def test_camel_case_and_compound_secret_keys_are_redacted() -> None:
    out = redact(
        {"accessToken": "a", "clientSecret": "b", "passphrase": "c", "api_key": "d", "apiKey": "e",
         "privateKey": "f", "x-auth-token": "g"}
    )  # fmt: skip
    assert set(out.values()) == {REDACTED}
    assert redact({"author": "Ada", "keyboard": "us", "authority": "x"}) == {
        "author": "Ada",
        "keyboard": "us",
        "authority": "x",
    }


def test_redaction_cannot_be_used_to_stall_the_gate() -> None:
    import time

    started = time.monotonic()
    for hostile in ("a." * 200_000, "x:" * 200_000, "http://" + "a" * 200_000):
        redact({"text": hostile, hostile[:50]: 1})
    assert time.monotonic() - started < 1.0
