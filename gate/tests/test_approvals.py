"""Approvals: bound to the exact call, one voice per person, single use, denied on timeout."""

from pathlib import Path

import pytest

from honeycomb_gate.approvals import Approval, ApprovalStore, call_key

TTL = 600


def ask(
    store: ApprovalStore,
    run: str = "run_1",
    tool: str = "crm__rotate_keys",
    quorum: int = 1,
    digest: str = "sha256:a",
    now: float = 1000.0,
    timeout: float = 120,
) -> tuple[Approval, bool]:
    return store.request(
        key=call_key(run, tool, digest),
        run_id=run,
        agent_id="support-bot",
        tool=tool,
        rule_id="approve-rotate",
        quorum=quorum,
        args_redacted={"x": 1},
        blast_radius="all keys",
        timeout_s=timeout,
        now=now,
    )


def test_an_approved_call_can_be_used_exactly_once(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    a, new = ask(store)
    assert new and a.status == "pending"
    assert store.consume(a.key, 1001) is None  # nothing is approved yet
    assert store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1005) == "ok"
    used = store.consume(a.key, 1010)
    assert used is not None and used.approvers == ["asha"]
    assert store.consume(a.key, 1011) is None  # single use


def test_quorum_needs_different_people(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    a, _ = ask(store, quorum=2)
    assert store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1001) == "ok"
    assert store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1002) == "duplicate"
    assert store.consume(a.key, 1003) is None  # one person twice is still one voice
    assert store.decide(a.id, "ravi", "approve", ttl_s=TTL, now=1004) == "ok"
    assert store.consume(a.key, 1005) is not None


def test_one_no_ends_it(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    a, _ = ask(store, quorum=2)
    store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1001)
    assert store.decide(a.id, "ravi", "deny", ttl_s=TTL, now=1002) == "ok"
    assert store.get(a.id).status == "denied"  # type: ignore[union-attr]
    assert store.decide(a.id, "sam", "approve", ttl_s=TTL, now=1003) == "closed"
    assert store.consume(a.key, 1004) is None


def test_a_request_nobody_answers_in_time_is_denied(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    a, _ = ask(store, now=1000, timeout=120)
    assert store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1121) == "expired"
    assert store.consume(a.key, 1122) is None
    b, _ = ask(store, digest="sha256:b", now=2000, timeout=120)
    assert [x.id for x in store.sweep(now=2200)] == [a.id, b.id]  # both ran out of time
    assert store.get(b.id).status == "expired"  # type: ignore[union-attr]
    assert store.sweep(now=2300) == []  # reported once


def test_an_approval_that_is_not_used_in_time_lapses(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    a, _ = ask(store)
    store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1010)
    assert store.consume(a.key, 1010 + TTL + 1) is None


@pytest.mark.parametrize("change", [{"run": "run_2"}, {"tool": "crm__disable_user"},
                                    {"digest": "sha256:changed"}])  # fmt: skip
def test_an_approval_is_for_that_call_only(tmp_path: Path, change: dict[str, str]) -> None:
    store = ApprovalStore(tmp_path)
    a, _ = ask(store)
    store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1001)
    other = call_key(
        change.get("run", "run_1"), change.get("tool", "crm__rotate_keys"),
        change.get("digest", "sha256:a"),
    )  # fmt: skip
    assert other != a.key and store.consume(other, 1002) is None
    assert store.consume(a.key, 1003) is not None  # the real call still works


def test_asking_twice_finds_the_same_open_request(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    first, new1 = ask(store)
    again, new2 = ask(store, now=1005)
    assert new1 and not new2 and first.id == again.id
    store.decide(first.id, "asha", "approve", ttl_s=TTL, now=1006)
    store.consume(first.key, 1007)
    third, new3 = ask(store, now=1008)  # used up, so a new call needs a new answer
    assert new3 and third.id != first.id


@pytest.mark.parametrize("bad", ["", "../../etc/passwd", "apr_../x", "apr_", "run_1", "apr_a b"])
def test_odd_ids_never_reach_the_filesystem(tmp_path: Path, bad: str) -> None:
    store = ApprovalStore(tmp_path)
    assert store.get(bad) is None
    assert store.decide(bad, "asha", "approve", ttl_s=TTL) == "unknown"


@pytest.mark.parametrize("again", ["Asha", "asha ", " ASHA", "as​ha", "ａsha", "asha\n"])
def test_one_person_typing_their_name_differently_is_still_one_voice(
    tmp_path: Path, again: str
) -> None:
    store = ApprovalStore(tmp_path)
    a, _ = ask(store, quorum=2)
    assert store.decide(a.id, "asha", "approve", ttl_s=TTL, now=1001) == "ok"
    assert store.decide(a.id, again, "approve", ttl_s=TTL, now=1002) == "duplicate"
    assert store.consume(a.key, 1003) is None


def test_an_empty_name_is_not_a_person(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path)
    a, _ = ask(store)
    for blank in ("", "   ", "​\n"):
        assert store.decide(a.id, blank, "approve", ttl_s=TTL, now=1001) == "unnamed"
    assert store.consume(a.key, 1002) is None
