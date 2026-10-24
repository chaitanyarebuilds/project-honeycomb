# Architecture decision records

One short file per decision that shapes the architecture, a schema or a security default. Add a new record (next number) before changing any of those. Status values: **Proposed** (needs the owner's OK), **Accepted**, **Superseded**. ADR-0001 to 0008 were accepted by the owner on 24 October 2026.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-own-core-with-plugin-seam.md) | Own thin core with a plugin seam (resolves D1) | Accepted |
| [0002](0002-gate-minted-run-identity.md) | Gate-minted run identity; no reliance on MCP sessions | Accepted |
| [0003](0003-data-plane-control-plane-split.md) | Deterministic data plane, separate control plane, no LLM in enforcement | Accepted |
| [0004](0004-enforcement-levels.md) | Enforcement levels and an honest posture report | Accepted |
| [0005](0005-tamper-evident-log.md) | Hash-chained event log from M1 | Accepted |
| [0006](0006-agent-presence-and-persistence.md) | Agent inventory, run lifetime limits, persistence and memory audit | Accepted |
| [0007](0007-incident-response-ladder.md) | Incident object, response ladder, notification and escalation | Accepted |
| [0008](0008-licence-hygiene.md) | No code from copyleft-with-exceptions projects; clean-room tokens | Accepted |
