# Development guide

Rules and setup for anyone contributing code to Project Honeycomb. For the ways to help and the scope rules, read [CONTRIBUTING.md](../CONTRIBUTING.md) first. The design is in [PHASE0-SPEC.md](PHASE0-SPEC.md), which is the source of truth for what Phase 0 builds.

## Non-negotiable rules

1. **Defensive only.** No tooling that attacks systems you do not own, no "hack back" features, no working exploits for unpatched third-party vulnerabilities, no malware.
2. **The lab stays in the lab.** The scripted attacker in `lab/` may only target lab containers on an internal Docker network. The restriction is hard-coded; do not add support for external targets.
3. **Synthetic data only.** Decoys, fixtures and lab data are generated. Never commit real personal data, credentials or customer data.
4. **No secrets in git.** Use `.env` (gitignored) and keep `.env.example` current. Honeytokens are generated at deploy time and never committed, because some look like real keys and trip secret scanners.
5. **Fail closed for high-impact tools.** If the policy engine or approval broker errors, block the call and raise an alert.
6. **Untrusted text is data, never instructions.** That covers tool descriptions, tool outputs, documents, logs and model output.

## Setup

You need Python 3.12 or newer and [uv](https://docs.astral.sh/uv/). On Windows 11, the lab runs on Docker Desktop with the WSL 2 backend. Prefer `uv run` entry points over shell scripts.

| Task | Command |
| --- | --- |
| Install | `uv sync` |
| Tests | `uv run pytest` |
| Lint and format | `uv run ruff check . --fix` then `uv run ruff format .` |
| Types | `uv run mypy gate/src` |
| Run the gate | `uv run honeycomb-gate run --config policies/example.yaml` |
| Validate a config and policy | `uv run honeycomb-gate policy check --config policies/example.yaml` |
| Read recent events | `uv run honeycomb-gate events tail --config policies/example.yaml` |
| Search events | `uv run honeycomb-gate events query --severity high --config policies/example.yaml` |
| Check the log has not been tampered with | `uv run honeycomb-gate events verify --config policies/example.yaml` |
| Review and approve a changed tool | `uv run honeycomb-gate tools list --config ...`, then `tools show upstream__tool --config ...`, then `tools approve upstream__tool --hash <pending hash> --config ...` |
| Lab (planned, M2 onward) | `docker compose -f lab/docker-compose.yml up --build -d`, then `uv run lab-run --scenario all` |

CI runs ruff, mypy and pytest on every pull request.

## Layout

```
gate/                 Python package honeycomb_gate (src layout) and its tests
  src/honeycomb_gate/
  tests/
lab/                  Docker Compose lab: targets, scripted attacker, egress proxy, scenarios
policies/             Example policy files
docs/                 Concept docs, the Phase 0 spec, threat model, prior art, lab results
scripts/              Repository maintenance only
```

## Conventions

- Small pull requests, one concern each. Update the tests and docs your change touches.
- Sign off every commit with `git commit -s` (see the Developer Certificate of Origin in CONTRIBUTING). Use Conventional Commit prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`.
- Licensing: Apache-2.0 for code, CC BY 4.0 for docs. No per-file licence headers.
- Event and policy schemas are public contracts. They carry a `schema_version`, and any change needs a note in PHASE0-SPEC.md.
- Justify every new dependency in the pull request description. Prefer the standard library and a few well-maintained packages.
- Every detection gets a test with a malicious example **and** a benign look-alike. False positives are tested as seriously as detections.
- Docs are plain English, and every factual claim cites a source (see [SOURCES.md](SOURCES.md)).
- Always write "Project Honeycomb" in full: honeycomb.io is an unrelated company.
- Map each control to the OWASP Top 10 for Agentic Applications (ASI01 to ASI10) in the spec as it is built.

## Changes that need maintainer sign-off first

Write an architecture decision record ([docs/adr/](adr/README.md)) and get it accepted before you:

- change the architecture or a schema;
- add a service;
- choose which agent clients to support first;
- change a security default (fail-open versus fail-closed, learning versus strict mode).
