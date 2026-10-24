# Backlog (M0 to M5)

Status: proposal, 24 October 2026. Every item has an ID, an owning role, a size (S ≤ 1 day, M ≤ 3 days, L ≤ 1 week) and acceptance criteria. Each one also has to meet the definition of done in [PROGRAM-PLAN.md](PROGRAM-PLAN.md). Items marked **ADR** depend on a decision in [docs/adr/](../adr/README.md).

## E0 Foundations (M0, mostly done)

| ID | Item | Role | Size | Acceptance |
| --- | --- | --- | --- | --- |
| E0-1 | Pass-through proxy and event log | Platform | M | Done: client to gate to sample server, events visible |
| E0-2 | CI on GitHub | Platform | S | ruff, mypy, pytest green on a pull request |
| E0-3 | Decide ADR-0001 to 0008 | Owner | S | Statuses updated |
| E0-4 | Licence and secret scan in CI | Security | S | Fails on a banned licence or a planted fake key |
| E0-5 | Contract test against MCP 2026-07-28 and 2025-11-25 | Platform | M | Both eras served; test in CI |

## E1 Event log (M1)

| ID | Item | Role | Size | Acceptance |
| --- | --- | --- | --- | --- |
| E1-1 | Schema v1 update: `run_id` required, `session_id` optional, `prev_hash`, `hash` (**ADR-0002, 0005**) | Platform | S | Spec note added; validation test |
| E1-2 | Redaction of keys, tokens and URLs with credentials | Detection | M | Malicious samples redacted; benign look-alikes untouched |
| E1-3 | SQLite index and `events query` | Platform | M | Filter by kind, severity, run, time; handles 1M events |
| E1-4 | Hash chain and `events verify` | Platform | M | Edited, deleted and reordered lines each detected |
| E1-5 | Second sink and rotation | Platform | M | Done in M1 except rotation. Checkpoints are written after every event; rotation has to keep the chain verifiable |
| E1-6 | Keyed hash chain and a remote sink | Security | M | The chain key lives outside the state directory, so an attacker who can rewrite local files cannot forge a valid chain or a valid sink |

## E2 Registry, pinning, policy (M1)

| ID | Item | Role | Size | Acceptance |
| --- | --- | --- | --- | --- |
| E2-1 | Tool hashing and pin store | Platform | M | Hash over name, description, schema; per upstream |
| E2-2 | Quarantine and `tools approve` | Platform | M | Changed tool hidden and uncallable until approved; events emitted |
| E2-3 | Suspicious-description flags | Detection | M | Test set with injected descriptions and benign long descriptions |
| E2-4 | Policy file, first-match rules, modes | Platform | L | Allow, deny, approve; learning and strict; unknown fields rejected |
| E2-5 | Fail closed on engine errors for high-impact tools | Platform | S | Fault-injection test blocks the call and raises `gate.error` |
| E2-6 | Scenario S2 as a pytest and then in the lab | Researcher | M | Mid-run description change quarantines the tool |
| E2-7 | `docs/THREAT-MODEL.md` | Security | L | STRIDE-style table for the gate and the lab; external review done |

## E3 Decoys and honeytokens (M2)

| ID | Item | Role | Size | Acceptance |
| --- | --- | --- | --- | --- |
| E3-1 | Decoy injection into `tools/list` with per-deployment vocabulary | Platform | M | Never collides with a real tool; excluded from baselines |
| E3-2 | Decoy trip: pause, revoke, incident, tarpit or error | Platform | L | Measured trip-to-pause under 2 s; call never forwarded |
| E3-3 | Tarpit responder from templates | Detection | M | Same question gives the same answer; response time configurable |
| E3-4 | Clean-room token generator (**ADR-0008**) | Detection | M | Four kinds; embedded id; never committed |
| E3-5 | Token scanner on arguments, responses and logs | Detection | M | Positive and look-alike tests; no false hit on real-looking non-tokens |
| E3-6 | Incident object and webhook notifier (**ADR-0007**) | Platform | L | Incident created on trip; message answers the five questions |
| E3-7 | Scenario S1 | Researcher | M | Decoy trips; session paused; no real export |

## E4 Identity, egress, presence (M3)

| ID | Item | Role | Size | Acceptance |
| --- | --- | --- | --- | --- |
| E4-1 | Run token mint, verify, revoke (**ADR-0002**) | Platform | L | Done in M3a: replay, expiry, tampering and revocation tests |
| E4-2 | Key management and rotation | Security | M | Done in M3a: keys outside the repo; rotation tested |
| E4-3 | Egress proxy with allowlist and log ingestion | Platform | L | Done in M3b: blocked request becomes `egress.blocked` |
| E4-4 | Lab on an internal Docker network | Researcher | L | Done in M3b: agent has no other route; the lab test proves it |
| E4-5 | Posture report (**ADR-0004**) | Platform | M | Done in M3a: reports the level correctly in the example setups, never above L2 |
| E4-6 | Agent inventory, strict-mode denial, run lifetime (**ADR-0006**) | Platform | L | Inventory, scopes and strict-mode denial done in M3a; hard run lifetime limits move to M4 |
| E4-7 | `audit mcp-config` | Detection | M | Flags unknown servers and unpinned versions |
| E4-8 | Scenario S3 | Researcher | M | Done in M3b: `egress.blocked` and `honeytoken.used` |

## E5 Governors and baselines (M4)

| ID | Item | Role | Size | Acceptance |
| --- | --- | --- | --- | --- |
| E5-1 | Approval broker: CLI and webhook, timeout denies | Platform | L | Done in M4: each decision logged with approver |
| E5-2 | Quorum and caps (rows, bytes, recipients, rate) | Platform | L | Done in M4 for rows, bytes and rate (recipient limits stay an argument matcher); quorum of N |
| E5-3 | Escalation and acknowledgement (**ADR-0007**) | Platform | M | Done in M4: an unacknowledged high or critical incident escalates after N seconds |
| E5-4 | Baseline profiler in learning mode | Detection | L | Done in M4: new tool, rate and volume deviations flagged |
| E5-5 | Alert deduplication and flood limit | Platform | M | Flood test produces one incident |
| E5-6 | Abuse tests: forced approvals, response triggering | Security | M | Attempts blocked; documented |
| E5-7 | Scenarios S4 and S0 | Researcher | L | Done in M4: S4 passes (test and Docker lab); S0 zero high or critical alerts |

## E6 Memory, lab report, release (M5)

| ID | Item | Role | Size | Acceptance |
| --- | --- | --- | --- | --- |
| E6-1 | Learned rules from incidents | Detection | L | `memory.rule_learned` and `memory.rule_matched` |
| E6-2 | Scenario S5 | Researcher | M | Fewer steps and less time than S1 |
| E6-3 | `lab-run` with JSON and Markdown results | Researcher | M | Results file per run |
| E6-4 | `docs/LAB-RESULTS.md` | Researcher | M | Real numbers; limits stated |
| E6-5 | OWASP agentic mapping table | Security | M | Every control mapped to ASI01 to ASI10 |
| E6-6 | README quick start and timed outside run | DevRel | M | New developer under 30 minutes |
| E6-7 | Playbooks (`docs/playbooks/`) | Security | M | Seven playbooks in [DEFENCE-MODEL.md](DEFENCE-MODEL.md) |
| E6-8 | Tag v0.1.0 | Owner | S | G5 passed |
