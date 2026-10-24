# ADR-0001: Own thin core with a plugin seam

Status: Accepted by the owner on 24 October 2026. Date: 2026-10-24. Resolves open decision D1.

## Context

We looked at two existing gateways. IBM ContextForge is Apache-2.0, active (last commit 23 October 2026) and has a plugin framework. Lasso's MCP Gateway is MIT, but it has had no commits since January 2026. A keyword search of both repositories found no decoy tools, honeytokens or tool-definition pinning in either. See [PRIOR-ART-MCP.md](../PRIOR-ART-MCP.md).

## Decision

We write our own small gate core: proxy, registry, policy, log, run identity, decoys and honeytokens. Every detector sits behind a narrow interface (`inspect_list(...)`, `inspect_call(...)`, `inspect_result(...)`) that returns allow, deny, approve or trip, with evidence. The core stays free of ContextForge types.

Our differentiators need hooks that a general gateway may not expose: pausing a run, revoking an identity, tarpit responses and the lab's determinism. The core is also small (the M0 proxy is about 150 lines on the official SDK), so owning it costs little. And the narrow detector interface means we could later package decoys and pinning as a ContextForge plugin, if that's where users turn out to be.

## Consequences

We now maintain the transport layer ourselves. To keep that manageable we track SDK releases (see [THREAT-WATCH.md](../program/THREAT-WATCH.md)).

We revisit this at the M2 gate. That means re-reading ContextForge's plugin API and its changelog, and reconsidering if it ships decoys and pinning.
