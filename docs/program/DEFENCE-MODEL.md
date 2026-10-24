# Defence model: first layer, containment and notification

Status: proposal, 24 October 2026. Detail for [ADR-0006](../adr/0006-agent-presence-and-persistence.md) and [ADR-0007](../adr/0007-incident-response-ladder.md).

## 1. What "first layer of defence" means here

Project Honeycomb is the first thing an agent meets when it tries to use an organisation's tools, and the last thing standing between a hijacked agent and the data. It doesn't replace endpoint, identity or web defences. It covers the agent surface that those tools mostly don't see.

## 2. How agents get in and stay (and what stops each step)

| Stage | What an attacker or runaway agent does | Control | Phase |
| --- | --- | --- | --- |
| Entry | Connects an unknown agent or tool server | Agent registration, run tokens, tool pinning, strict mode | M1 to M3 |
| Entry | Poisoned tool description or rug pull | Pinning, quarantine, description flags | M1 |
| Entry | Injection in a document, web page or tool output | Decoys catch the resulting action; honeytokens catch use; caps and approvals limit damage | M2, M4 |
| Reach | Asks for more data or a bigger tool than its job needs | Least-privilege scopes in the run token, caps | M3, M4 |
| Exfiltration | Sends data out | Default-deny egress, honeytoken scan on arguments, responses and egress logs | M2, M3 |
| Persistence | Stays alive past its task, re-registers, plants config, schedules itself, writes poisoned memory | Run lifetime limit, inventory, config audit, memory scan | M3, Phase 1 |
| Evasion | Edits logs, floods alerts, triggers our own response against us | Hash-chained log, second sink, deduplication, response limits, governors | M1, M4 |
| Collusion | Two agents converge on the same unusual behaviour | Cross-agent baseline check (stretch) | M4 |

## 3. Response ladder

| Step | Action | Triggered by | Reversible |
| --- | --- | --- | --- |
| 0 | Log | any event | n/a |
| 1 | Alert | medium and above | n/a |
| 2 | Slow: rate limit or tarpit | baseline deviation, suspicious description | yes |
| 3 | Pause the run | decoy or honeytoken trip | yes, a human resumes |
| 4 | Revoke run identity, quarantine tool or upstream | decoy or honeytoken trip, definition change | yes, new token or `tools approve` |
| 5 | Isolate the agent (egress deny-all) | policy only; off by default outside the lab | yes |
| 6 | Rotate credentials | human approval, quorum for critical | no |

Steps 3 and 4 run automatically on a trip, because trips are high-fidelity and reversible. Steps 5 and 6 can hurt the business, so a person is always in the loop (see the autoimmunity discussion in [ARCHITECTURE.md](../ARCHITECTURE.md)). Governors cap how much any action can touch.

## 4. Notifying the IT or security team

### The incident message

Every incident answers five questions in its first lines:

1. **What happened?** One sentence ("Agent `support-bot` called decoy tool `crm__export_all_customer_data`").
2. **How sure are we?** The detection type, and why a legitimate run would not do this.
3. **What did the gate already do?** For example "run paused, identity revoked at 10:15:02".
4. **What should you do now?** Ordered steps, such as review the evidence, check the upstream's access log, decide whether to rotate credentials X and Y.
5. **How protected are we?** The enforcement level (L0 to L3) and anything the gate could not stop.

Evidence (event ids, redacted arguments, timeline) follows. Secrets are redacted before storage and again before sending.

### Delivery and escalation

| Time | Action |
| --- | --- |
| 0 | Critical incident to the primary channel (webhook or CLI in Phase 0) |
| N min (default 10) without acknowledgement | Escalate to the secondary channel |
| 2N | Escalate again and repeat until acknowledged |
| Always | Written to the second log sink that the agent cannot touch |

Duplicate alerts for the same run are merged into one incident within a time window. Acknowledging is a logged action (`honeycomb-gate incidents ack`).

### Later (managed service)

A human operations centre receives the same incidents for customers with no security team. CERT-In six-hour and DPDP 72-hour reporting would be drafted from the incident record (`regulatory_clock_start`). That is a separate business decision, covered in [HARD-PROBLEMS.md](../HARD-PROBLEMS.md), problem 7.

## 5. Playbooks to write (M2 to M5)

- Decoy tripped by an agent (confirm, resume or rotate).
- Honeytoken seen in egress logs.
- Tool definition changed (approve or investigate the upstream).
- Unknown agent connected.
- Run exceeded lifetime.
- Approval flood or forced-response attempt.
- Log chain broken.

Each playbook is a one-page file in `docs/playbooks/` with the trigger, checks, decisions and rollback.
