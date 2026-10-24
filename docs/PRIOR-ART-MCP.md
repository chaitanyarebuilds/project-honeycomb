# Prior art: MCP gateways, scanners and decoys

Status: M0 survey, 24 October 2026. Update, 24 October 2026: ContextForge, Lasso, Thinkst Canarytokens and the official MCP specification repository have now been cloned and read, and their rows below are marked **verified**. Rows still marked unconfirmed come from search summaries and listings, and need the same check. Findings are summarised in [program/ARCHITECTURE-REVIEW.md](program/ARCHITECTURE-REVIEW.md) and [program/MARKET-AND-GAPS.md](program/MARKET-AND-GAPS.md).

## Summary table

| Project | What it covers (Phase 0 feature) | Licence | Confidence |
| --- | --- | --- | --- |
| [IBM ContextForge](https://developer.ibm.com/blogs/context-forge-mcp-gateway-now-available/) | Gateway with pre/post plugin hooks: PII, content filtering, rate limits, policy (F1, F4) | Apache-2.0 | **Verified**: `LICENSE` read; last commit 23 Oct 2026; no decoy, honeytoken or definition-pinning code found by keyword search |
| [Lasso Security MCP Gateway](https://www.sourcepulse.org/projects/11158170) | Plugin gateway: secret and PII masking, prompt-injection checks, tool-description scanner (F1, F3) | MIT | **Verified** licence; last commit 22 Jan 2026 (about nine months quiet); features still from listings |
| [Docker MCP Gateway](https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/) | Container-isolated MCP servers, image signing, interceptors, secret blocking (F1) | Open source, licence not named in sources | Unconfirmed |
| [Microsoft MCP Gateway](https://microsoft.github.io/mcp-gateway/deployment/infra/) | Kubernetes reverse proxy and management layer, C# (F1) | Not found | Unconfirmed |
| [Snyk Agent Scan (formerly Invariant mcp-scan)](https://invariantlabs.ai/blog/introducing-mcp-scan) | Scans for tool poisoning, shadowing and rug pulls; pins tool hashes (F3) | Sources disagree (Apache-2.0 reported for the Snyk repo) | Unconfirmed |
| [Thinkst Canarytokens](https://blog.thinkst.com/2026/06/one-for-all-the-models-out-there.html) | Honeytokens; added an MCP token type in 2026 (F5, F6 ideas) | **Verified:** GPL v3 plus extra clauses that treat integrating, linking or executing it as a derivative work; Thinkst sells other licences | We may reuse ideas only ([ADR-0008](adr/0008-licence-hygiene.md)) |
| agent-canary | Decoy MCP tools and canary strings; any call is treated as hijack (F5, F6) | MIT | Single listing |
| HoneyMCP | "Ghost tools" as middleware for FastMCP servers (F5) | Apache-2.0 | Single listing, about 19 stars |
| Beelzebub | General honeypot framework with an MCP honeypot mode (F5) | Not checked | Not checked |

Sources for the last three: [agent-canary](https://mcpservers.org/servers/dorianchn/agent-canary), [HoneyMCP](https://lobehub.com/mcp/barvhaim-honeymcp), [Beelzebub](https://awesome.ecosyste.ms/projects/github.com%2Fbeelzebub-labs%2Fbeelzebub), [Zeltser's DIY decoy write-up](https://zeltser.com/decoy-mcp-server-honeypot).

## What this means

1. Decoys and honeytokens on their own are not new. Three open-source projects and Thinkst already do decoy MCP tools. Our edge has to be the combination: a decoy trip that also pauses the run, revokes identity and feeds learned rules (S5), plus egress control and approvals, in one lab that anyone can run. That's a weaker claim than "first deception layer for agents", and the docs shouldn't make the stronger one.
2. Gateways with policy hooks exist. ContextForge is the strongest candidate to build on: Apache-2.0, with a plugin hook model. It's also large, with many features we don't need, so adopting it brings a heavy dependency and its own attack surface.
3. We found no open-source gateway that combines policy proxying with decoys, honeytokens, run identity and approvals. Absence from search results isn't proof, so we should repeat the check by reading the repos.
4. The protocol is moving. The MCP spec revision 2026-07-28 and Python SDK 2.x change how sessions work (see `docs/PHASE0-SPEC.md` section 1a). Any gateway we build on must already support that, which is another reason to check each project's current state.

## Recommendation for D1 (for Chaitanya to decide)

**Keep our own minimal proxy for M0 and M1**, as the spec's default says, and re-run this survey by reading the repos before starting M2. The reasons:

- The M0 proxy is about 150 lines on the official SDK, so owning it costs little.
- The spec's decision rule needs a permissively licensed, well-maintained gateway that covers F1 to F4. Only ContextForge clearly passes the licence test, and we haven't yet read its code.
- Our differentiators (F5, F6, F7, F9, F10, memory) need hooks at session and run level that a general gateway may not expose.

The alternative, if you'd rather go fast, is to build F5 to F10 as ContextForge plugins. We'd have to judge its plugin API first, which is roughly a day of reading.

## Next checks (needs network access to GitHub)

- [ ] Read `LICENSE` for each project above and replace "unconfirmed".
- [ ] Read ContextForge's plugin hook API and decide whether F5/F6 fit.
- [ ] Check whether any listed gateway supports the 2026-07-28 MCP revision.
- [ ] Add the OWASP agentic mapping once controls exist.
