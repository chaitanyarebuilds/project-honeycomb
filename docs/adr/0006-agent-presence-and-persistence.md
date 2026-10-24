# ADR-0006: Agent inventory, run lifetime limits, persistence and memory audit

Status: Accepted (owner approval, 24 October 2026). Date: 2026-10-24. Adds features F13 and F14.

## Context

The goal is to keep hostile or runaway agents out of systems and stop them living there. The current design reacts to a bad call. CERT-In's advisory (CIAD-2026-0049) describes agents reaching live systems and nobody noticing. Presence and persistence need their own controls.

## Decision

**F13. Agent inventory and run limits (Phase 0, M3).**
- Every `agent_id` and run seen by the gate goes into an inventory with first seen, last seen, tools used and upstreams reached.
- Agents must be registered in policy. An unregistered agent is denied in strict mode and raised as `agent.unknown` in learning mode.
- Runs have a maximum lifetime. Renewal beyond it needs policy permission or approval, so no agent identity lives indefinitely.
- `honeycomb-gate audit mcp-config <path>` scans MCP client configs for unknown servers, unpinned versions and unexpected changes.

**F14. Persistence and memory audit (Phase 1).**
- Detect and flag creation of scheduled tasks, new credentials, new tool registrations or new MCP servers made through tool calls.
- Scan agent memory and workspace stores for instruction-like text and for honeytokens.

## Consequences

- Two new event kinds (`agent.unknown`, `run.expired`) and one CLI group (`audit`).
- Feeds the incident manager (ADR-0007) as ordinary signals.
