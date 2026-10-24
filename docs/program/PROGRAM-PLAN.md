# Programme plan

Status: proposal, 24 October 2026. Owner: Chaitanya Pandita. The product phases (0 to 4) are in [ROADMAP.md](../ROADMAP.md). This file covers **how** we deliver them: workstreams, gates, staffing, measures and what would make us stop or change course.

## 1. Mission and scope of the first product

Project Honeycomb is a defensive layer that sits first in line between an organisation's AI agents and its systems. It has four jobs, in this order:

1. **Keep out.** Only registered, least-privileged agents get in. Tools are pinned and untrusted, and nothing leaves except through an allowlist.
2. **Catch fast.** Decoys, honeytokens and baselines make a hijacked or runaway agent visible in seconds with almost no false alarms.
3. **Stop and contain.** Pause, revoke and isolate, within limits people set.
4. **Tell the humans.** The IT or security team gets an incident that says what happened, what the gate already did and what to do next, with escalation if nobody answers.

A fifth job, **don't let agents live in the system**, runs through all four: inventory, short run lifetimes, persistence and memory audits ([ADR-0006](../adr/0006-agent-presence-and-persistence.md)).

## 2. Delivery structure

### 2.1 Workstreams

| ID | Workstream | Scope | Lead role |
| --- | --- | --- | --- |
| WS-A | Gate core | Transport, registry, pinning, policy, run identity, decoys, honeytokens | Platform engineer |
| WS-B | Detection | Detectors, baselines, learned rules, false-positive tests | Detection engineer |
| WS-C | Response | Incident manager, response ladder, notifier, approvals, escalation | Platform engineer |
| WS-D | Lab and evidence | Docker lab, scripted attacker, scenarios S0 to S5, metrics, published results | Security researcher |
| WS-E | Security of the gate | Threat model, abuse tests, dependency and licence checks, red team | Security lead |
| WS-F | Docs and community | Quick start, contributor guide, videos, issue triage, threat watch | DevRel and docs |
| WS-G | Compliance and legal | DPDP, IT Act position on active measures, CERT-In workflows | Legal adviser (external) |

### 2.2 Phases, gates and exit criteria

We split Phase 0 so each stage ends in something we can demonstrate. A **gate** is a go or no-go review by the owner, and the evidence for each gate lives in the repository.

| Stage | Window | Contents | Gate and exit criteria |
| --- | --- | --- | --- |
| M0 Foundations | week 1 | Scaffold, pass-through proxy, research, ADRs | **G0:** ADRs 0001 to 0008 decided; D1 decided; CI green on GitHub |
| M1 Firewall | weeks 2 to 3 | Event log with hash chain, pinning and quarantine, policy engine, threat model | **G1:** scenario S2 passes in CI; log verifies; threat model reviewed by someone outside the team |
| M2 Decoys | weeks 3 to 4 | Decoy tools, tarpit, honeytokens, incident manager v0 | **G2 (first public demo):** S1 passes; trip to pause under 2 s measured; incident reaches a webhook |
| M3 Identity and egress | weeks 5 to 6 | Run identity, key management, egress proxy, agent inventory, posture report | **G3:** S3 passes fully; posture report correct at L0 to L2; unregistered agent denied in strict mode |
| M4 Governors and baselines | weeks 7 to 8 | Approvals, quorum, caps, baselines, escalation | **G4:** S4 passes; S0 (50 benign sessions) shows zero high or critical alerts |
| M5 Memory and release | weeks 9 to 10 | Learned rules, `lab-run`, results report, OWASP mapping, v0.1.0 | **G5:** S0 to S5 pass in CI; an outside developer runs the lab from the README in under 30 minutes on Windows or Linux |
| M6 Pilot readiness | weeks 11 to 16 | Packaging, hardening, 2 to 3 design partners running L2 | **G6:** 30 days of partner use with no governor bypass and a reviewed false-positive log |

After G6 the programme follows the product roadmap: Phase 1 web shield (4 to 9 months, a separate product line, managed service), Phase 2 mesh and sentinels, Phase 3 specialists and red-team vaccination, Phase 4 herd immunity. Each gets its own plan file when it is ten weeks away.

### 2.3 Weekly rhythm

- Monday: plan the week from [BACKLOG.md](BACKLOG.md) and name one demo for the week.
- Daily: a short async update (done, next, blocked).
- Friday: demo, update [RISK-REGISTER.md](RISK-REGISTER.md), run the threat watch ([THREAT-WATCH.md](THREAT-WATCH.md)), and update the milestone checklist.
- At every gate: a one-page review covering evidence, metrics and decisions needed.

### 2.4 Definition of done (every item)

An item is done when it has code, tests with a malicious example and a benign look-alike, and docs. It also needs an ADR if architecture or a schema changed, the OWASP agentic mapping updated, CI green, review by someone who did not write it, and no secrets or real data.

## 3. Measures

| Measure | Target by G5 | How measured |
| --- | --- | --- |
| Time from malicious step to trip (S1) | under 2 seconds | lab metrics |
| False positives in S0 | 0 high or critical alerts in 50 sessions | lab metrics |
| Added latency per tool call | under 20 ms at p99 on the lab machine | benchmark in CI |
| S5 vs S1 | fewer steps and less time | lab metrics |
| Tamper test | any edit to the log detected | `events verify` test |
| Outside developer setup | under 30 minutes | timed dry run with someone new |

## 4. Resources and access needed

| Need | For | Status |
| --- | --- | --- |
| Working repository push | all | Working since 24 October |
| SMTP account for incident email | M2 notifier | Provided by the owner; kept only in a local `.env`, never in git. Not reachable from the build sandbox, so tested against a local fake mail server and then by the owner |
| Docker daemon in the build environment | the lab (M3 onward) | Works. The CLI is installed and we start the daemon by hand with `dockerd`; images pull and internal networks have no route out (checked 25 October). It has to be started again in each new session, or added to the environment's setup script |
| A GitHub account or two for review | independent review | Needed from the owner |
| An outside security reviewer (a few hours per gate) | WS-E | A community developer will review the threat model |
| A webhook endpoint for tests | M2 and M4 notifications | Local test receiver in the lab |
| An API key for an LLM (optional) | the real-LLM lab agent | Optional, stored only in `.env` |
| Legal adviser (Indian IT Act and DPDP) | before any active measure ships | Not engaged. We test only on our own systems and keep counter-injection off; revisit before any pilot with real data |
| Two to three design-partner organisations | M6 | Owner to introduce |

## 5. Staffing assumption

Confirmed 24 October 2026: two people (the owner and the CTO) plus coding agents ([TEAM-AND-AGENTS.md](TEAM-AND-AGENTS.md)). The two people split the roles in section 1 of that file, and coding agents do most of the implementation, testing and drafting under human review. Read the dates in section 2.2 as targets, and expect the human review step to be the bottleneck. If M1 takes more than three weeks, we cut M4 baselines first and keep decoys, tokens, identity and egress.

## 6. Risks and kill criteria

The full list is in [RISK-REGISTER.md](RISK-REGISTER.md). We stop or change course if:

- At G2, the trip-to-pause time can't get under 5 seconds on the lab machine. The core design is then wrong.
- At G4, S0 still shows false positives after two tuning rounds. Decoy-first detection is then not the near-zero-false-positive signal we assumed.
- At any time, a major gateway ships decoys, honeytokens and pinning as defaults. Then we switch to the plugin route in ADR-0001 and focus on governors, the lab and the managed service.
- At any time, legal advice says counter-injection or any active measure is unsafe in India. We keep it off, as the spec already does.
