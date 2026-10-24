# Market, competitors and gaps

Status: working document, 24 October 2026. Facts marked **verified** were read from the project's own repository or licence file. **Reported** means a secondary source (listing, news, vendor page) that we haven't confirmed. Update this file whenever [THREAT-WATCH.md](THREAT-WATCH.md) finds a change.

## 1. Who does what (agent and MCP layer)

| Product | What it does | Licence and activity | Confidence |
| --- | --- | --- | --- |
| IBM ContextForge | MCP gateway with a plugin framework (PII, filters, schema guard, webhook notification, watchdog, policy decision plugin and others). No decoy, honeytoken or definition-pinning code found by keyword search | Apache-2.0; last commit 23 Oct 2026 | Verified (shallow clone) |
| Lasso MCP Gateway | Plugin gateway: secret and PII masking, prompt-injection checks, tool-description scanning | MIT; last commit 22 Jan 2026 | Verified licence and date; features reported |
| Docker MCP Gateway | Containerised MCP servers, signed images, interceptors | Open source; licence not confirmed | Reported |
| Microsoft MCP Gateway | Kubernetes reverse proxy and management layer | Not confirmed | Reported |
| Snyk Agent Scan (ex Invariant mcp-scan) | Scans MCP servers and agents for poisoning, shadowing and rug pulls; hashes tool descriptions | Sources disagree on licence | Reported |
| Thinkst Canarytokens | Honeytokens, including an MCP token type added in 2026 | GPL v3 with extra derivative-work clauses; last commit 21 Oct 2026 | Licence verified; MCP token reported |
| agent-canary, HoneyMCP, Beelzebub | Decoy MCP tools and canary strings; small projects | MIT, Apache-2.0, not checked | Reported |
| Acalvio ShadowPlex | Deception platform; announced deception guardrails for tool-using agents in July 2026 | Commercial | Reported (vendor announcement) |
| Darktrace | Autonomous anomaly response; popularised the immune-system idea for networks | Commercial | Reported |
| Large platform buy-ins (Palo Alto Networks, Check Point, SentinelOne, F5, CrowdStrike) | Acquired AI-agent security start-ups in 2025 to 2026 and fold gateways into platforms | Commercial | Reported ([PipeLab tracker](https://pipelab.org/blog/ai-agent-security-acquisition-wave-2026/)) |

## 2. How they work and where they fall short

| Pattern | How it works today | Gap we can fill |
| --- | --- | --- |
| Prompt and response filters in a gateway | Inspect text for injection, secrets, PII | Text filters are probabilistic and can be evaded. We don't depend on classifying text: a decoy call or a token use is a deterministic fact |
| Tool scanners | Scan once, or at install time | Scan-time checks miss mid-run changes. Pinning with quarantine at call time closes the rug-pull window |
| Decoy and honeytoken projects | Small tools or a hosted token service | They detect and alert. They don't pause the run, revoke its identity, enforce egress or measure the result in a lab |
| Platform "agent security" modules | Bundled with a large suite | Costly and complex for small organisations; closed; no public evidence of containment results |
| Gateways with plugins | General policy and filters | No agent-lifetime controls, no inventory, no incident and escalation path aimed at the IT team |
| Human approval | Often a UI click in the gateway | Rarely tied to blast-radius caps, quorum and timeouts-deny, and rarely tested in a lab |

## 3. Where Honeycomb is different (hypotheses to test, not claims)

1. Deterministic detection first. Decoys, honeytokens and pinning give us evidence, not scores.
2. Containment, not just detection. A trip pauses the run, revokes its identity and starts an incident within seconds, and we publish the measured time.
3. Honesty about enforcement. The product states its enforcement level, so nobody mistakes an advisory gate for a wall ([ADR-0004](../adr/0004-enforcement-levels.md)).
4. Agents that stay. Inventory, lifetimes, persistence and memory audits are aimed at agents living inside a system, something gateways rarely address ([ADR-0006](../adr/0006-agent-presence-and-persistence.md)).
5. Evidence in public: a lab anyone can run, with scenarios and numbers.
6. A fit for small organisations. One command to run, sensible defaults, and a notification path that works without a security team.

What we should **not** claim: that decoys or honeytokens are new, that we are the first, or that we stop attacks that bypass the gate on an unenforced network.

## 4. How attackers are changing (design inputs)

Sources: the research report behind the video series and [SOURCES.md](../SOURCES.md).

| Trend | What it means for the design |
| --- | --- |
| Exploitation before patches (mean time to exploit about -7 days, Mandiant M-Trends 2026) | Controls must work without a patch, so rely on behaviour, pinning and egress control |
| Access hand-off in 22 seconds (Mandiant) | Automatic containment for high-fidelity signals; humans arrive after |
| Agents running attacks, such as GTG-1002 (Anthropic, estimated 80 to 90 percent of tactical work) | Defend against agent-speed action: rate limits, decoys, run lifetimes |
| Credential harvesting by agents in hours (Google, September 2026) | Honeytokens and egress scanning; short-lived run identities |
| Agents escaping sandboxes and reaching live systems (OpenAI incident; CERT-In CIAD-2026-0049) | Network-level default-deny, agent inventory, tamper-resistant logs |
| Injection through tools, documents and logs | Treat all text as untrusted; deterministic enforcement; no model in the decision path |
| Third parties in 48 percent of breaches (Verizon DBIR 2026) | Pin and scope every upstream; treat upstream servers as untrusted |

## 5. Feature ideas from the market for the backlog

- A scanner mode that audits existing MCP client configs (ADR-0006, F13).
- Signed tool manifests, if the MCP ecosystem converges on one (watch item).
- An export of incidents in a standard format (for example, OpenTelemetry events or a SIEM-friendly JSON), so security teams can ingest them.
- Canary-style one-line deployment for decoys, to match the effort small teams expect.

## 6. Questions this analysis cannot yet answer

- Real licences and release cadence for Docker, Microsoft and Snyk projects (blocked network; needs a reading of each repository).
- Whether any gateway already ships decoys by default. Re-run the keyword search on a schedule ([THREAT-WATCH.md](THREAT-WATCH.md)).
- Customer willingness to pay. This needs the design-partner conversations in [PROGRAM-PLAN.md](PROGRAM-PLAN.md).
