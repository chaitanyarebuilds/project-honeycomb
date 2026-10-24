"""What must never be in the repository: secrets, tool attribution, private addresses.

These are the project's own rules turned into a test, so a slip fails CI instead of reaching
the public history. It scans only the files git tracks.
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Built from pieces, so this file does not match its own patterns.
ATTRIBUTION = [
    "Co-" + "Authored-By",
    "Generated " + "with",
    "claude." + "ai/code",
    "Claude " + "Code",
    "noreply@" + "anthropic",
    "Claude-" + "Session",
    "\U0001f916",  # the robot emoji that tool footers like to add
]
PRIVATE = ["@gmail" + ".com", "cmo" + "@", "wolfrom" + "technologies", "chetana" + "panta"]
SECRETS = {
    "an AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "a private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "an API key": re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}"),
    "a fine-grained GitHub token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"),
    "a Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    "a Hugging Face token": re.compile(r"\bhf_[A-Za-z0-9]{30,}"),
    "a GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "a Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
}


# Fake keys that the redaction tests use on purpose. Anything else that looks like a key fails.
KNOWN_FAKES = [
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "sk-live-" + "abcdefghijklmnop1234",
    "sk-test-" + "0123456789abcdefghij",
]


def tracked() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [ROOT / p for p in out.decode().split("\0") if p]


def text_of(path: Path) -> str | None:
    try:
        return path.read_text("utf-8")
    except (UnicodeDecodeError, OSError):
        return None  # binary or gone


def hits(patterns: list[str]) -> list[str]:
    found = []
    for path in tracked():
        text = text_of(path)
        if text is None or path.name == "uv.lock":
            continue
        found += [f"{path.relative_to(ROOT)}: {p}" for p in patterns if p.lower() in text.lower()]
    return found


def test_no_file_names_a_tool_as_author() -> None:
    assert hits(ATTRIBUTION) == []


def test_private_addresses_and_names_are_not_in_the_repository() -> None:
    assert hits(PRIVATE) == []


def test_nothing_that_looks_like_a_real_secret_is_committed() -> None:
    found = []
    for path in tracked():
        text = text_of(path)
        if text is None:
            continue
        for fake in KNOWN_FAKES:
            text = text.replace(fake, "")
        found += [
            f"{path.relative_to(ROOT)}: {what}"
            for what, pattern in SECRETS.items()
            if pattern.search(text)
        ]
    assert found == []


def test_the_private_working_notes_and_runtime_state_are_not_tracked() -> None:
    names = {str(p.relative_to(ROOT)) for p in tracked()}
    assert "CLAUDE.md" not in names and ".env" not in names
    assert not [n for n in names if n.startswith("lab/results/") or "/.honeycomb/" in n]
    assert not [n for n in names if n.endswith((".sqlite3", "tokens.json", "identity-keys.json"))]


def test_commit_messages_carry_no_attribution_or_private_addresses() -> None:
    try:
        log = subprocess.run(
            ["git", "log", "-200", "--format=%an <%ae>%n%B%x00"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    lowered = log.lower()
    assert [p for p in ATTRIBUTION + PRIVATE if p.lower() in lowered] == []
