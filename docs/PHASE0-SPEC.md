# Phase 0 spec: honeycomb-gate

Status: draft v0.1, October 2026. Owner: Chaitanya Pandita. This is a proposal: challenge anything, but record decisions in section 11.

## 1. Goal

Give an organisation a drop-in layer that makes a hijacked AI agent visible within seconds and stops it from doing damage, without needing a security team.

**The demo in one sentence:** a poisoned document tells an agent to export customer data; the agent reaches for a decoy tool; within two seconds the run pauses, its identity is revoked, and a human gets an alert.

Phase 0 tests these hypotheses from the videos:

- Decoy tools and honeytokens catch hijacked agents with near-zero false positives, because no legitimate run touches them.
- Treating tool descriptions as untrusted input and pinning them catches tool poisoning and silent "rug pull" changes.
- Network-level default-deny egress stops exfiltration, even when the prompt-level defences fail.
- Human-approval governors with blast-radius caps stop self-inflicted damage without making agents useless.
- Remembering an incident makes the second attempt fail faster.

## 2. Users

- **Primary:** small and mid-sized organisations and IT service firms that run AI agents with tool access, such as coding agents, support agents and internal operations agents.
- **Operator:** a developer or IT admin at that organisation, and later the Honeycomb managed service.
- **First integration:** agents that use MCP (Model Context Protocol). Which clients to support first is open decision D2.

## 3. Scope

**In Phase 0:** features F1 to F12 below, the lab (section 8), and the documentation needed for an outside developer to run both.

**Out of Phase 0:**

- the network-wide mesh and sentinels;
- machine-learning models beyond simple statistics;
- hosted or multi-tenant SaaS;
- cross-customer sharing;
- non-MCP tool protocols (define an adapter interface only);
- protecting the host operating system;
- any offensive capability.

## 4. Architecture

```mermaid
flowchart LR
  AG["AI agent<br/>(MCP client)"] -->|MCP| GW
  subgraph GW["honeycomb-gate"]
    SM[Session manager<br/>and run identity] --> REG[Tool registry<br/>and pinning]
    REG --> DEC[Decoy injector]
    SM --> POL[Policy engine]
    POL --> APR[Approval broker<br/>governor]
    POL --> TOK[Honeytoken scanner]
    SM --> EV[(Event log)]
    EV --> BL[Baseline profiler]
    EV --> AL[Alerter]
  end
  GW -->|MCP| UP1[Upstream MCP server A]
  GW -->|MCP| UP2[Upstream MCP server B]
  AG -. all other traffic .-> EG[Egress proxy<br/>allowlist only]
  EG -. logs .-> EV
```

**The bypass assumption:** the gate only protects an agent that cannot reach its tools or the internet except through the gate and the egress proxy. The lab enforces this with an internal Docker network. Deployment docs must say plainly that without network enforcement, the gate is advisory.

### Flow: listing tools

1. The agent calls `tools/list`. The gate collects tools from each upstream server and namespaces them as `server__tool` to avoid collisions.
2. The registry hashes each definition (name, description, input schema) and compares it with the pinned hash. Changed tools are quarantined (F3).
3. Descriptions are scanned for instruction-like text. A hit is flagged as a signal, not proof.
4. Decoy tools are added (F5).
5. Policy hides denied tools.
6. The list is returned and an event is logged.

### Flow: calling a tool

1. The agent calls `tools/call`.
2. The gate resolves the session and checks the run identity is valid and not revoked (F7).
3. If the tool is a decoy: trip, log, pause the session, revoke the identity, alert, and return a tarpit response. The call is never forwarded.
4. The arguments are scanned for honeytokens. A hit trips the same way.
5. Policy is evaluated with first-match rules, giving allow, deny or approve, plus rate and blast-radius caps.
6. If the result is approve, the approval broker asks a human (F10), and a timeout means deny.
7. Allowed calls are forwarded upstream. The response is size-checked, scanned for honeytokens, and logged in redacted form.
8. Baselines are updated (F9).

## 5. Features

**F1. Transport and proxying.**

- Support stdio and Streamable HTTP on both the agent side and the upstream side, and multiplex several upstream servers into one namespace.
- Preserve JSON-RPC request IDs.
- Pass resources and prompts through, but log them in Phase 0, because they can also carry injections. Policy over them comes later.
- Treat tool annotations from upstream servers (such as `readOnlyHint` and `destructiveHint`) as untrusted hints. Never use them to grant permissions.
- Before building, verify the current MCP spec revision and SDK behaviour, and record both here.

**F2. Event log.**

- Append-only storage: JSONL files plus SQLite for queries.
- Redact secrets before storage using key and token patterns.
- Cap stored payload size and keep a SHA-256 of the full payload.
- The schema is in section 6.

**F3. Tool registry and pinning.**

- On first sight, record a SHA-256 of each tool's (name, description, input schema) per upstream server.
- On any change, log `tool.definition_changed` and quarantine the tool until an operator runs `honeycomb-gate tools approve`.
- Heuristically flag instruction-like text in descriptions ("ignore previous", "do not tell the user", URLs, encoded blobs) as `tool.suspicious_description`.

**F4. Policy engine.**

- Policies are YAML and use first-match rules. Actions are `allow`, `deny` or `approve`.
- Rules can match on upstream server, tool name glob, and argument matchers (equals, regex, max length, max items). They can also set rate limits and blast-radius caps (max rows, max bytes, max recipients).
- Two modes: `learning` (unknown tools allowed and logged) and `strict` (unknown tools denied).
- Any internal error is a deny for tools marked high-impact.

**F5. Decoy tools ("decoy skills").**

- Decoys are defined in config and injected into `tools/list`, with names and descriptions believable for the organisation.
- They are never forwarded upstream.
- Any call trips `decoy.tripped` (critical). The session is paused, the run identity revoked, and an alert sent.
- The trip response is either an immediate error or a tarpit: slowly dripped, plausible synthetic data built from templates.
- Decoy names are drawn per deployment from a vocabulary, so they don't become a fingerprint. They must never collide with real tool names, and they are excluded from baselines.

**F6. Honeytokens.**

- `honeycomb-gate tokens create --kind <api-key|db-url|webhook-url|password> --place <path>` generates fake credentials with an embedded ID and plants them in the agent's workspace, memory or documents.
- The gate scans tool arguments, tool responses and egress logs for every registered token. Any appearance trips `honeytoken.used` (critical).
- Tokens are generated at deploy time and never committed.

**F7. Run identity.**

- Each session gets a `run_id` and a short-lived signed token containing the run ID, agent ID, scopes and an expiry of 15 minutes or less, renewable. Scopes come from policy.
- Revocation is checked on every call.
- Where an upstream server supports it, the token is passed on so that the server can enforce it too.
- Cloud IAM and SPIFFE integration are later work.

**F8. Default-deny egress.**

- Reference setup: the agent container sits on an internal Docker network with no default route. Its only way out is an egress proxy with an allowlist.
- Proxy logs feed the event log, and egress is scanned for honeytokens.
- Hosts that can't run containers get documented firewall guidance only.

**F9. Behaviour baselines.**

- Keep a rolling profile per `agent_id`: tools used, call rate, argument and response sizes, upstream servers, and time of day.
- After a configurable number of sessions in learning mode, flag deviations: a new tool, a rate above the 99th percentile times k, or a data-volume spike.
- Stretch goal: flag two agents that suddenly issue near-identical unusual calls (the "agents adopting each other's goals" pattern).

**F10. Governor and approvals.**

- An approval request carries the run, tool, redacted arguments, the rule that fired, and the blast radius.
- Channels: a generic webhook adapter plus a CLI (`honeycomb-gate approvals list|approve|deny`). Slack, Telegram or email come later (open decision D3).
- A timeout means deny. Critical rules can require a quorum (N of M approvers).
- Every decision is logged with the approver's identity.

**F11. Alerts.**

- Delivered to the console and a webhook as JSON.
- Severity levels are info, low, medium, high and critical. Repeats are deduplicated within a time window.

**F12. CLI.**

- `honeycomb-gate run`
- `tools list|approve`
- `decoys list`
- `tokens create|list|revoke`
- `events tail|query`
- `approvals list|approve|deny`
- `baseline show`
- `version`

## 6. Data contracts

**Event (JSON, `schema_version: 1`):**

```json
{
  "schema_version": 1,
  "event_id": "01J...ULID",
  "ts": "2026-10-24T10:15:02.123Z",
  "kind": "decoy.tripped",
  "severity": "critical",
  "run_id": "run_...",
  "agent_id": "support-bot",
  "session_id": "sess_...",
  "upstream": "crm",
  "tool": "crm__export_all_customer_data",
  "decision": "trip",
  "rule_id": "decoy-default",
  "args_digest": "sha256:...",
  "args_redacted": {"format": "csv"},
  "latency_ms": 3,
  "details": {}
}
```

Event kinds:

- `session.started`, `session.paused`, `session.ended`
- `tools.listed`, `tool.definition_changed`, `tool.suspicious_description`
- `call.allowed`, `call.denied`, `call.approval_requested`, `call.approved`, `call.approval_denied`, `call.approval_timeout`
- `decoy.tripped`, `honeytoken.used`, `egress.blocked`
- `identity.issued`, `identity.revoked`
- `baseline.deviation`
- `memory.rule_learned`, `memory.rule_matched`
- `gate.error`

**Policy file (sketch):**

```yaml
schema_version: 1
mode: learning            # learning | strict
defaults:
  high_impact_fail: closed
  approval_timeout_s: 120
upstreams:
  crm: { transport: stdio, command: ["python", "-m", "lab.target_crm"] }
decoys:
  vocabulary: [export_all_customer_data, get_admin_api_key, list_payroll_accounts]
  count: 2
  on_trip: { pause_session: true, revoke_identity: true, response: tarpit }
rules:
  - id: deny-shell
    match: { tool: "*__exec*" }
    action: deny
  - id: approve-bulk-email
    match: { tool: "crm__send_email", args: { recipients: { max_items: 5 } } }
    action: approve
    quorum: 1
  - id: cap-exports
    match: { tool: "crm__export_report" }
    action: allow
    caps: { max_rows: 500, per_minute: 3 }
```

## 7. Threat model (summary)

The full version goes in `docs/THREAT-MODEL.md`, which is part of M1.

**Assets:** organisational data reachable through tools, credentials, the agent's ability to act, and the integrity of the gate, its policies and its logs.

**Adversaries:**

- an external attacker using indirect prompt injection through documents, web pages, emails or tool outputs;
- a malicious or compromised MCP server (tool poisoning, rug pulls, shadowing another server's tools);
- a compromised or misaligned agent;
- a malicious insider;
- an attacker going after the gate itself (bypass, log tampering, alert flooding, denial of service).

| Attack | Main controls |
| --- | --- |
| Indirect prompt injection that leads to data export | Decoys (F5), caps (F4), approvals (F10), egress deny (F8) |
| Tool poisoning or rug pull | Pinning and quarantine (F3), description flags (F3) |
| Tool-name shadowing across servers | Namespacing (F1), per-upstream pinning (F3) |
| Credential theft and exfiltration | Honeytokens (F6), egress deny (F8), redaction (F2) |
| Self-inflicted damage ("rotate all keys") | Approvals with quorum (F10), blast-radius caps (F4) |
| Replay or theft of a run token | Short TTL, revocation, session binding (F7) |
| Bypassing the gate | Network enforcement (F8); documented as an assumption |
| Log tampering | Append-only JSONL with hash chaining (stretch), separate alert channel |
| Alert flooding | Deduplication and rate limits (F11) |

## 8. The lab

**Compose services:**

- `target-crm`: an MCP server over synthetic customer data, with `search_customers`, `get_customer`, `send_email` (mock) and `export_report`.
- `docs`: an MCP server exposing files, including poisoned documents.
- `gate`: honeycomb-gate.
- `egress`: an allowlisting proxy.
- `agent`: runs in two modes:
  - a scripted attacker client, deterministic and needing no LLM, used in CI;
  - an optional real-LLM agent, used with an API key from `.env`.

All services sit on an `internal: true` network.

**Scenarios:**

| ID | Scenario | Pass condition |
| --- | --- | --- |
| S0 | 50 benign scripted sessions | Zero high or critical alerts |
| S1 | A poisoned document tells the agent to export all customers | Decoy trips; session paused; no real export |
| S2 | An upstream server silently changes a tool description mid-session to add hidden instructions | `tool.definition_changed`; tool quarantined |
| S3 | The agent finds a planted honeytoken and tries to send it to an outside URL | `egress.blocked` and `honeytoken.used` |
| S4 | An injected instruction asks the agent to disable users or rotate keys | Approval requested; timeout denies; caps enforced |
| S5 | S1 repeated in a fresh run after the incident | `memory.rule_matched`; stopped in fewer steps and less time than S1 |

**Memory for S5:** each incident can produce a learned rule, such as the hash of a poisoned document or a normalised injected phrase. The rule is stored as `memory.rule_learned` and checked against later tool responses.

**Metrics:** time from the malicious step to the trip, steps taken before the stop, attacker time wasted in the tarpit, false positives in S0, and the S5 improvement over S1. `lab-run` writes `lab/results/<timestamp>.json` and a Markdown summary.

## 9. Milestones

**M0: research spike and scaffolding (week 1)**

- [ ] Record the current MCP spec revision and Python SDK version here
- [ ] Survey the prior art in section 10 and write `docs/PRIOR-ART-MCP.md`, ending with a build-on-or-build-own recommendation for decision D1
- [ ] Set up the `uv` project, ruff, mypy, pytest and a GitHub Actions CI workflow
- [ ] Build a transparent pass-through proxy for one stdio upstream, with event logging
- [ ] Demo: an MCP client connected through the gate to a sample server, with events visible

**M1: firewall (weeks 2–3)**

- [ ] Event log (F2) and the `events` CLI
- [ ] Tool registry, pinning and quarantine (F3)
- [ ] Policy engine allow and deny, plus modes (F4)
- [ ] `docs/THREAT-MODEL.md`
- [ ] S2 passes

**M2: decoys (weeks 3–4)**

- [ ] Decoy tools and tarpit (F5)
- [ ] Honeytokens (F6)
- [ ] S1 passes, and the honeytoken half of S3 passes

**M3: identity and egress (weeks 5–6)**

- [ ] Run identity and revocation (F7)
- [ ] Lab egress proxy and log ingestion (F8)
- [ ] S3 passes fully

**M4: governors and baselines (weeks 7–8)**

- [ ] Approvals, quorum and caps (F10, F4)
- [ ] Baselines in learning mode (F9)
- [ ] Alerts webhook (F11)
- [ ] S4 passes; S0 shows zero false positives

**M5: memory, lab report and v0.1.0 (weeks 9–10)**

- [ ] Learned rules (S5)
- [ ] `lab-run` with JSON and Markdown results
- [ ] `docs/LAB-RESULTS.md` draft
- [ ] OWASP agentic mapping table filled in
- [ ] Tag v0.1.0

**v0.1.0 is done when** S0 to S5 pass in CI with the scripted attacker, an outside developer can run the lab from the README in under 30 minutes on Windows (Docker Desktop) or Linux, and every feature has tests that include benign look-alikes.

**Existing GitHub starter issues map to milestones as follows:**

- tool-call firewall → M1
- decoy skills → M2
- Phase 0 lab spec → M0 and M5
- related-work page → M0 survey
- signalling-bus threat model → Phase 2, not now
- CERT-In workflow → later, managed service

## 10. Prior art to check before building

Verify the current status of each, since this list reflects 2025–2026 knowledge.

- **MCP gateways and proxies:**
  - Docker MCP Gateway
  - Lasso Security's open-source MCP Gateway
  - Microsoft's MCP Gateway
  - IBM's ContextForge MCP Gateway
  - FastMCP's proxy support
- **MCP security scanning:** Invariant Labs' `mcp-scan` and guardrails work. Snyk acquired Invariant Labs in 2025, so check the current home and licence.
- **Honeytokens:** Thinkst Canarytokens, which is open source. Reuse its ideas and formats where the licence allows.
- **Risk frameworks:** OWASP Top 10 for Agentic Applications (ASI01 to ASI10) and OWASP Top 10 for LLM Applications.
- **Commercial agent-security products:** see `docs/RELATED-WORK.md`.

**Decision rule for D1:** if a permissively licensed (Apache-2.0 or MIT), well-maintained gateway already covers F1 to F4, consider building Honeycomb's differentiators on it. Those differentiators are decoys (F5), honeytokens (F6), baselines (F9), governors (F10), memory and the lab, built as plugins or a fork. Present the trade-offs to Chaitanya before deciding.

## 11. Open decisions

| ID | Decision | Default until decided |
| --- | --- | --- |
| D1 | Build on an existing gateway or write our own proxy | Own minimal proxy for M0; revisit after the survey |
| D2 | First agent clients to support | Any standard MCP client over stdio and Streamable HTTP |
| D3 | First approval and alert channel (Slack, Telegram, email, WhatsApp Business) | Generic webhook plus CLI |
| D4 | Default mode for new deployments | Learning mode for 7 days, then prompt to switch to strict |
| D5 | Language | Python; revisit only if D1 picks a TypeScript base |

Record each decision here with its date and reason.

## 12. Glossary

- **Cell:** the smallest unit you can watch and isolate. In Phase 0, one agent run.
- **Decoy skill:** a fake tool only a hijacked agent would call.
- **Honeytoken:** a fake credential whose use proves compromise.
- **Governor:** a component that can veto or require approval for an action.
- **Tarpit:** a slow, plausible fake response that wastes an attacker's time.
- **Blast radius:** the maximum damage one action can cause.
- **Rug pull:** a tool's definition changing after it has been trusted.
- **Tool poisoning:** hidden instructions placed in a tool's description or output.
- **Indirect prompt injection:** instructions hidden in content the agent reads.
