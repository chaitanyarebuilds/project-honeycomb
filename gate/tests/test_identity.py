"""Run tokens: the good one passes, and every way of forging, replaying or outliving one fails."""

import base64
import json
import os
import stat
import time
from pathlib import Path

import pytest

from honeycomb_gate.identity import KEY_ENV, MAX_TTL_S, Identities, KeyRing, TokenError


def make(tmp_path: Path) -> Identities:
    return Identities(tmp_path / "identities.json", KeyRing(tmp_path / "identity-keys.json"))


def forge(token: str, **changes: object) -> str:
    """Change a claim but keep the old signature: all an attacker without the key can do."""
    head, body, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims.update(changes)
    new = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{head}.{new}.{sig}"


def test_a_fresh_token_verifies_and_carries_its_claims(tmp_path: Path) -> None:
    ids = make(tmp_path)
    run_id, token = ids.issue("support-bot", ["crm__*"])
    claims = ids.verify(token)
    assert (claims.run_id, claims.agent_id, claims.scopes) == (run_id, "support-bot", ("crm__*",))
    assert 0 < claims.expires - claims.issued <= MAX_TTL_S


@pytest.mark.parametrize("ttl", [0, -5, MAX_TTL_S + 1])
def test_a_token_cannot_live_longer_than_fifteen_minutes(tmp_path: Path, ttl: int) -> None:
    with pytest.raises(TokenError):
        make(tmp_path).issue("a", ["*"], ttl_s=ttl)


def test_an_expired_token_is_refused(tmp_path: Path) -> None:
    ids = make(tmp_path)
    _, token = ids.issue("a", ["*"], ttl_s=60)
    ids.verify(token, now=time.time() + 59)
    with pytest.raises(TokenError, match="expired"):
        ids.verify(token, now=time.time() + 61)


@pytest.mark.parametrize("change", [{"scopes": ["*"]}, {"agent": "admin"}, {"exp": 9999999999}])
def test_a_tampered_payload_fails_the_signature(tmp_path: Path, change: dict[str, object]) -> None:
    ids = make(tmp_path)
    _, token = ids.issue("support-bot", ["crm__search*"])
    with pytest.raises(TokenError, match="bad signature"):
        ids.verify(forge(token, **change))


@pytest.mark.parametrize(
    "junk", ["", "hc1", "hc1.a.b", "x.y.z", "hc1." + "A" * 50 + ".B", "Bearer"]
)
def test_garbage_is_not_a_token(tmp_path: Path, junk: str) -> None:
    with pytest.raises(TokenError):
        make(tmp_path).verify(junk)


def test_a_revoked_run_cannot_be_used_or_renewed(tmp_path: Path) -> None:
    ids = make(tmp_path)
    run_id, token = ids.issue("a", ["*"])
    assert ids.revoke(run_id, "decoy.tripped") and not ids.revoke(run_id, "again")
    with pytest.raises(TokenError, match="revoked"):
        ids.verify(token)
    with pytest.raises(TokenError):
        ids.renew(run_id)


def test_renewing_gives_a_new_token_for_the_same_run(tmp_path: Path) -> None:
    ids = make(tmp_path)
    run_id, first = ids.issue("a", ["*"], ttl_s=60)
    second = ids.renew(run_id)
    assert (
        ids.verify(second).run_id == run_id
        and ids.verify(second).expires > ids.verify(first).expires
    )


def test_a_token_for_a_run_this_gate_never_issued_is_refused(tmp_path: Path) -> None:
    ours = make(tmp_path / "ours")
    _, token = ours.issue("a", ["*"])
    other = make(tmp_path / "other")
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "identity-keys.json").write_text(
        (tmp_path / "ours" / "identity-keys.json").read_text()
    )  # same key, but this gate has no record of the run
    with pytest.raises(TokenError, match="no such identity"):
        other.verify(token)


def test_a_token_signed_with_another_key_is_refused(tmp_path: Path) -> None:
    _, token = make(tmp_path / "one").issue("a", ["*"])
    with pytest.raises(TokenError):
        make(tmp_path / "two").verify(token)


def test_rotating_the_key_keeps_recent_tokens_valid_until_pruned(tmp_path: Path) -> None:
    ids = make(tmp_path)
    _, old = ids.issue("a", ["*"])
    assert ids.keys.rotate() != "k1"
    _, new = ids.issue("a", ["*"])
    assert ids.verify(old).kid == "k1" and ids.verify(new).kid != "k1"
    assert ids.keys.prune() == []  # too young to drop
    data = json.loads(ids.keys.path.read_text())
    data["keys"]["k1"]["created"] -= 3 * MAX_TTL_S
    ids.keys.path.write_text(json.dumps(data))
    assert ids.keys.prune() == ["k1"]
    with pytest.raises(TokenError, match="key"):
        ids.verify(old)
    ids.verify(new)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_the_key_file_is_private(tmp_path: Path) -> None:
    ids = make(tmp_path)
    ids.issue("a", ["*"])
    assert stat.S_IMODE(ids.keys.path.stat().st_mode) == 0o600


def test_a_key_from_the_environment_is_used_and_must_be_long_enough(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, "short")
    with pytest.raises(TokenError, match="32"):
        make(tmp_path).issue("a", ["*"])
    monkeypatch.setenv(KEY_ENV, "k" * 40)
    ids = make(tmp_path)
    _, token = ids.issue("a", ["*"])
    assert ids.verify(token).kid == "env" and not ids.keys.path.exists()


def test_rotating_after_a_prune_never_reuses_a_live_key_id(tmp_path: Path) -> None:
    ids = make(tmp_path)
    ids.issue("a", ["*"])
    seen = {"k1"}
    for _ in range(6):
        data = json.loads(ids.keys.path.read_text())
        for entry in data["keys"].values():
            entry["created"] -= 3 * MAX_TTL_S  # all old, so a prune drops everything but current
        ids.keys.path.write_text(json.dumps(data))
        ids.keys.prune()
        kid = ids.keys.rotate()
        assert kid not in seen
        seen.add(kid)
    _, fresh = ids.issue("a", ["*"])
    ids.verify(fresh)


def test_one_token_has_one_spelling(tmp_path: Path) -> None:
    ids = make(tmp_path)
    _, token = ids.issue("a", ["*"])
    for variant in (
        token + "=",
        token + "==",
        token + "!!",
        token[:-1] + ("B" if token[-1] != "B" else "C"),
    ):
        with pytest.raises(TokenError):
            ids.verify(variant)
    ids.verify(token)


def test_a_deeply_nested_payload_is_a_refusal_not_a_crash(tmp_path: Path) -> None:
    ids = make(tmp_path)
    body = base64.urlsafe_b64encode(b"[" * 20000).rstrip(b"=").decode()
    with pytest.raises(TokenError):
        ids.verify(f"hc1.{body}.AAAA")


@pytest.mark.parametrize("agent", ["", "a b", "a\nb", "x" * 65, "\x1b[31m", "über"])
def test_agent_ids_are_plain(tmp_path: Path, agent: str) -> None:
    with pytest.raises(TokenError):
        make(tmp_path).issue(agent, ["*"])


def test_renew_can_narrow_the_scopes(tmp_path: Path) -> None:
    ids = make(tmp_path)
    run_id, _ = ids.issue("a", ["*"])
    assert ids.verify(ids.renew(run_id, scopes=["docs__*"])).scopes == ("docs__*",)
