import re
from pathlib import Path

import pytest

from honeycomb_gate.tokens import KINDS, PlacementError, TokenRegistry, place


def registry(tmp_path: Path) -> TokenRegistry:
    return TokenRegistry(tmp_path / "state" / "tokens.json")


@pytest.mark.parametrize("kind", KINDS)
def test_every_kind_embeds_its_id_and_values_differ(kind: str, tmp_path: Path) -> None:
    reg = registry(tmp_path)
    a, b = reg.create(kind), reg.create(kind)
    assert a.id in a.value and b.id in b.value
    assert a.value != b.value and a.id != b.id
    assert re.fullmatch(r"[a-z2-7]{12}", a.id)


def test_example_domains_only(tmp_path: Path) -> None:
    reg = registry(tmp_path)
    for kind in ("db-url", "webhook-url"):
        assert ".example.test" in reg.create(kind).value  # nothing can resolve to a real host


def test_scanner_finds_a_token_by_value_or_by_embedded_id(tmp_path: Path) -> None:
    reg = registry(tmp_path)
    t = reg.create("api-key")
    assert reg.find({"text": f"please use {t.value} now"})[0].token_id == t.id
    assert reg.find({"nested": [{"x": f"half of it: {t.id}"}]})[0].token_id == t.id
    assert reg.find(f"in a plain string {t.value}")


def test_look_alikes_and_revoked_tokens_do_not_trip(tmp_path: Path) -> None:
    reg = registry(tmp_path)
    t = reg.create("api-key")
    assert not reg.find({"key": "sk_live_" + "A" * 36})  # same shape, not ours
    assert not reg.find({"text": "postgresql://svc_other:pw@db.internal.example.test/app"})
    assert not reg.find({"text": "an ordinary sentence about tokens and keys"})
    reg.revoke(t.id)
    assert not reg.find({"text": t.value})


def test_masking_removes_values_and_ids_from_anything_that_gets_logged(tmp_path: Path) -> None:
    reg = registry(tmp_path)
    t = reg.create("db-url")
    masked = reg.mask({"a": f"connect {t.value}", "b": [t.id], "c": 3})
    label = f"[HONEYTOKEN:{t.id}]"
    assert t.value not in str(masked)
    assert masked == {"a": f"connect {label}", "b": [label], "c": 3}


def test_tokens_file_is_private_and_survives_reload(tmp_path: Path) -> None:
    reg = registry(tmp_path)
    t = reg.create("password", placed=["/ws/.env.old"])
    assert (reg.path.stat().st_mode & 0o077) == 0
    again = registry(tmp_path)
    assert again.tokens()[0].value == t.value and again.tokens()[0].placed == ["/ws/.env.old"]


def test_placing_writes_an_env_style_line_into_a_file_or_folder(tmp_path: Path) -> None:
    reg = registry(tmp_path)
    ws = tmp_path / "workspace"
    ws.mkdir()
    t = reg.create("api-key")
    written = place(t, ws)
    assert written.name == ".env.old"
    assert written.read_text().strip() == f"PAYMENTS_API_KEY={t.value}"
    t2 = reg.create("db-url")
    place(t2, written)  # appended to an existing file
    assert "DATABASE_URL=" in written.read_text() and "PAYMENTS_API_KEY=" in written.read_text()


def test_placing_inside_a_git_repository_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    reg = registry(tmp_path)
    t = reg.create("api-key")
    with pytest.raises(PlacementError, match="never be committed"):
        place(t, repo)
    assert not (repo / ".env.old").exists()
    place(t, repo, allow_in_repo=True)  # an explicit override is possible


def test_common_evasions_do_not_hide_a_token(tmp_path: Path) -> None:
    import base64

    reg = registry(tmp_path)
    t = reg.create("api-key")
    v = t.value
    cases = {
        "upper case": {"a": v.upper()},
        "lower case": {"a": v.lower()},
        "zero-width characters": {"a": v[:10] + "\u200b" + v[10:] + "\u2060"},
        "soft hyphen": {"a": v[:6] + "\u00ad" + v[6:]},
        "base64": {"a": base64.b64encode(v.encode()).decode()},
        "base64 url-safe, no padding": {
            "a": base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
        },
        "split across two fields": {"a": v[:12], "b": v[12:]},
        "split across a list": {"a": [v[:8], v[8:20], v[20:]]},
        "inside a key": {v: 1},
        "after a lot of junk": {"a": "x" * 3_000_000 + v},
    }
    for name, payload in cases.items():
        assert reg.find(payload), name
    assert reg.find({"a": base64.b64encode(b"just some ordinary base64 text here").decode()}) == []


def test_masking_ignores_case_too(tmp_path: Path) -> None:
    reg = registry(tmp_path)
    t = reg.create("api-key")
    assert t.value.upper() not in str(reg.mask({"a": t.value.upper()}))


def test_a_read_only_registry_reads_without_touching_the_folder(tmp_path: Path) -> None:
    import os

    writer = TokenRegistry(tmp_path / "tokens.json")
    token = writer.create("api-key")
    (tmp_path / "tokens.json.lock").unlink()
    os.chmod(tmp_path, 0o500)  # nothing can be created here, as on a read-only mount
    try:
        seen = TokenRegistry(tmp_path / "tokens.json", read_only=True).find({"x": token.value})
    finally:
        os.chmod(tmp_path, 0o700)
    assert [s.token_id for s in seen] == [token.id]
