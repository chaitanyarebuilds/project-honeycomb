# ADR-0001: Own thin core with a plugin seam

Status: Accepted (owner approval, 24 October 2026). Date: 2026-10-24. Resolves open decision D1.

## Context

IBM ContextForge is Apache-2.0, active (last commit 23 October 2026) and has a plugin framework. Lasso's MCP Gateway is MIT but had no commits since January 2026. Neither implements decoy tools, honeytokens or tool-definition pinning (keyword search of both repositories). See [PRIOR-ART-MCP.md](../PRIOR-ART-MCP.md).

## Decision

Write our own small gate core (proxy, registry, policy, log, run identity, decoys, honeytokens). Put every detector behind a narrow interface (`inspect_list(...)`, `inspect_call(...)`, `inspect_result(...)`) that returns allow, deny, approve or trip with evidence. Keep the core free of ContextForge types.

## Why

- Our differentiators need hooks a general gateway may not expose: run pause, identity revocation, tarpit responses and the lab's determinism.
- The core is small (the M0 proxy is about 150 lines on the official SDK), so owning it is cheap.
- A narrow detector interface lets us later package decoys and pinning as a ContextForge plugin if that is where users are.

## Consequences

- We carry maintenance of the transport layer. We mitigate that by tracking SDK releases (see [THREAT-WATCH.md](../program/THREAT-WATCH.md)).
- Revisit at the M2 gate: re-read ContextForge's plugin API and its changelog. If it ships decoys and pinning, reconsider.
