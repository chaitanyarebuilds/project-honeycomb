# Threat model: honeycomb-gate (M1)

Status: first version, 24 October 2026, covering what exists after M1 (event log, pinning, policy). We update it at every milestone. **A community developer should review it before gate G1**; findings go in section 8. Method: list assets and trust boundaries, then walk each component asking what an attacker could do, what stops them, how we test it and what remains.

## 1. Scope

In scope: the gate process, its config and state files (`pins.json`, the event log, the second sink), its CLI, and the link between agent, gate and upstream servers.

Out of scope for M1: the host operating system, the agent's own model, network enforcement (M3), decoys and honeytokens (M2), run tokens (M3), approvals (M4). Where a control belongs to a later milestone, the table says so, so nobody assumes it already exists.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Data and actions reachable through upstream tools | What a hijacked agent would steal or damage |
| Pinned tool definitions (`pins.json`) | Decide which tool definitions the gate trusts |
| Policy file | Decides allow and deny |
| Event log and second sink | Evidence; the basis of incidents |
| Operator approvals | Turn a quarantined tool back on |

## 3. Trust boundaries

```mermaid
flowchart LR
  A["Agent<br/>(untrusted)"] -->|MCP| G
  subgraph TB["Gate host (trusted)"]
    G[Gate process] --- S[("State: pins, log, sink path")]
    C[Operator CLI] --- S
  end
  G -->|MCP| U["Upstream MCP servers<br/>(untrusted)"]
  U -.->|tool definitions, results| G
```

The agent, the upstream servers and everything they send (descriptions, results, errors) are untrusted. The gate host, the operator and the policy file are trusted. Without network enforcement (M3), nothing stops the agent bypassing the gate. The product treats that as enforcement level L0 or L1 ([ADR-0004](adr/0004-enforcement-levels.md)).

## 4. Adversaries

1. A malicious or compromised upstream MCP server (poisoned descriptions, rug pulls, shadowing, hostile results).
2. Indirect prompt injection steering the agent through documents, pages or tool output.
3. A compromised or runaway agent.
4. A local attacker or insider with some access to the gate host.
5. An attacker attacking the gate itself: flooding, malformed input, log tampering.

## 5. Threats and controls

Status: **Done** (built and tested in M1), **Later** (planned milestone), **Accepted** (residual risk we are choosing to carry).

| # | Threat | Control | Status | Test | Residual risk |
| --- | --- | --- | --- | --- | --- |
| T1 | Upstream changes a tool definition after trust is established (rug pull) | Per-tool SHA-256 over everything the agent sees (name, title, description, input and output schemas, annotations, execution hints); any change quarantines the tool; the operator must approve the exact pending hash after viewing a diff (`tools show`, `tools approve --hash`). A definition swapped right after an approval is quarantined too | Done | `test_scenario_s2`, `test_registry` | The default re-checks the live definition on every call (`recheck_ttl_s: 0`), at the cost of one extra upstream round trip. Raising it creates a window in which a changed tool is still trusted; a demo with a 2 s window let a poisoned tool through, which is why 0 is the default |
| T2 | Poisoned description from first sight (trust on first use) | Instruction-like text anywhere in a definition (description, title, schema fields) is flagged as `tool.suspicious_description`; strict mode requires approval before a tool is visible | Done (flags are signals) | `test_registry` malicious and benign sets | Learning mode pins a poisoned first definition; use strict mode for untrusted upstreams. Heuristics can be evaded |
| T3 | Tool-name shadowing or ambiguous routing across upstreams | Names are namespaced `upstream__tool`; upstream names are limited to lower-case letters, digits and `-`, so routing is unambiguous; pins are per upstream | Done | `test_ambiguous_upstream_names_are_rejected` | None known |
| T4 | Misleading tool annotations ("read only") or hidden metadata | Annotations are never used for any decision (but are pinned, so a change quarantines); `_meta` and icons are not forwarded to the agent | Done | `test_forwarded_tools_carry_no_unpinned_metadata`, `test_hash_covers_everything_the_agent_sees` | None known |
| T5 | Call to an unknown, hidden or quarantined tool by guessing its name | Resolved against live definitions; quarantined or unapproved tools are denied; policy hides denied tools from the list | Done | `test_passthrough`, `test_scenario_s2`, `test_a_definition_swapped_right_after_approval_is_still_caught` | None known |
| T6 | Over-broad or dangerous call (e.g. `exec`, 500 recipients) | First-match policy with tool, upstream and argument matchers. A deny rule treats a missing or wrong-typed argument as a match, so changing an argument's type does not slip past a limit; a rule that errors at runtime fails closed if it is a deny rule; high-impact patterns (`*exec*`, `*shell*`, `*delete*`, `*drop*`, `*truncate*`, `*destroy*`, `*wipe*`, case-insensitive) fail closed on error; `approve` and caps refuse to load until M4 | Done (allow, deny) / Later (approve, caps) | `test_policy` | Until M4 there is no human approval path |
| T7 | Policy typo silently weakens protection | Unknown fields rejected; unsupported features and invalid regular expressions refuse to load; argument matchers must name a tool or upstream; `policy check` command | Done | `test_policy` | A logically wrong rule still loads |
| T8 | Secrets written into logs | Key-based redaction (camelCase, snake_case and compound names such as `accessToken`, `api_key`) and value-based redaction before storage; agent-chosen names (`tool`, `upstream`) are redacted, stripped of control characters and shortened; strings are capped before scanning; digest of the full payload kept | Done | `test_events` (redaction, names), `test_passthrough` | New secret formats can slip through; redaction is best effort. State files are readable only by their owner, and the SQLite index is a convenience copy, not evidence |
| T9 | Attacker edits, deletes or reorders log lines | SHA-256 hash chain; `events verify` | Done | `test_events` | The hash is unkeyed: an attacker who can rewrite the log **and** the second sink can recompute everything (see T10). Backlog E1-6: keyed chain with the key held elsewhere, and a remote sink |
| T10 | Attacker truncates, deletes or replaces the log or the sink | A checkpoint (count and chain head) goes to the second sink after **every** event, plus full copies of high and critical events; the sink file is created at start, so a missing sink or a missing log fails `events verify`; one writer per log (a second gate is refused rather than forking the chain); a torn last line stops the gate instead of continuing a broken chain | Done if the sink is on storage the attacker cannot write | `test_events` | Same-account attackers can still rewrite both files. Later: remote sink |
| T11 | Attacker with write access to `pins.json` re-approves a poisoned tool or forges the recorded approver | Not prevented: state files are trusted (they are created readable only by their owner, and access is serialised with a file lock) | Accepted | n/a | Protect the state directory. Later: sign approvals; take approver identity from the approval broker |
| T12 | Approver identity is only the OS user name | Recorded in `tool.approved` | Accepted | n/a | Weak attribution. Later: approver identity from the approval broker (M4) |
| T13 | Log flooding or oversized input exhausts disk, memory or CPU | Lines capped at 8 KiB (tool and upstream names shortened to 128 characters, strings to 8 KiB before any scan); redaction patterns are bounded and tested for stalling; pagination capped at 100 pages with repeated cursors refused | Partial | `test_events`, `test_gate_robustness` | No rate limit on call volume yet; add in M4 with deduplication |
| T14 | Hostile tool results carry injections or planted secrets | Results are scanned for registered honeytokens (value or embedded id) and withheld on a hit; text classification is deliberately not used for decisions ([ADR-0003](adr/0003-data-plane-control-plane-split.md)) | Done for honeytokens | `test_honeytokens_in_gate`, `test_common_evasions_do_not_hide_a_token` | Injected instructions in results are not detected; the decoy catches the action they cause. Matching ignores case and invisible characters, sees through base64 and values split across fields or list items, and covers the tool name too. Not matched: other encodings (rot13, hex, home-made ciphers) and a token reassembled by the attacker's own code. Calls over 4 million characters are refused so nothing can be hidden past a scan limit |
| T15 | Agent bypasses the gate | Not enforceable by software alone | Later (M3) | n/a | Enforcement levels make this explicit; lab uses an internal network |
| T16 | Stolen or replayed identity | No run tokens yet; one run id per connection | Later (M3) | n/a | See ADR-0002 |
| T17 | Hijacked agent touches a decoy or honeytoken | Decoy tools in `tools/list` and honeytokens in the workspace. A trip pauses the run and opens an incident, automatically. "Revoking the identity" currently means the run id is retired and every call from it is refused; signed run tokens that other systems can check arrive in M3. A call already in flight when another call trips is not forwarded, and further trips are logged as evidence without opening more incidents. The pause survives a gate restart: a restarted gate starts paused until `runs resume` | Done | `test_scenario_s1`, `test_honeytokens_in_gate` | An agent that never touches a decoy or token is not caught by this control |
| T18 | A denied call leaks policy details to the attacker | Agent sees one generic message; reason is only in the log | Done | `test_passthrough` | The tool list itself reveals what exists |
| T21 | The audit record is lost after the action happened | The decision is logged **before** the call is forwarded; if the log cannot be written, the call does not happen. A second event, `call.completed`, records the outcome | Done | `test_a_call_is_not_forwarded_if_the_decision_cannot_be_logged` | A crash between the two events leaves a decision with no outcome, which is visible |
| T22 | An operator approves a definition they did not review | Approval requires the pending hash and fails if the definition changed since it was shown | Done | `test_approval_needs_the_hash_the_operator_reviewed` | The operator must still read the diff |
| T23 | Decoys are recognisable (names, descriptions, timing, data shape) | Per deployment: names drawn from a vocabulary, one of three wordings, row count, id range, phone prefix, a reserved example domain and the tarpit delay all differ; responses are seeded by the call (same question, same answer); no model in the response path | Partial | `test_decoys` | The built-in vocabulary and wording variants are public, so an attacker who knows the project can recognise the defaults; operators should add their own names and descriptions. An identical repeated call gets an identical answer on purpose |
| T24 | Honeytoken values leak into logs, incidents, emails or errors | Values are masked (ignoring case) in arguments, tool names and everything logged; incidents carry the token id only; text chosen by the agent is cleaned and shortened before it goes into an incident, so it cannot add fake sections to an email; the agent sees a generic block message | Done for exact values | `test_honeytokens_in_gate`, `test_tokens`, `test_gate_robustness` | A token the agent re-encodes before logging could appear encoded in `args_redacted` (it is a fake, but the claim "never logged" is only for the exact value). Token values sit in plaintext in `tokens.json` (readable only by the owner); someone who can read it learns which credentials are fake |
| T25 | Mail credentials leak or a mail outage weakens containment | Credentials come from the environment, are not passed to upstream servers (`upstreams.<name>.env` is the only environment they get), never appear in errors or logs; sending runs after the run is paused, off the hot path | Done | `test_a_mail_outage_does_not_weaken_containment_or_leak_secrets`, `test_notify` | The environment of the gate process holds the password, so anyone who can read that process's environment can read it |
| T26 | A tripped run is resumed by the attacker, or the pause is shaken off | Resume is a CLI action by an operator who can write the state directory; it retires the old run id and issues a new one. A restart does not clear the pause | Accepted | `test_resume_issues_a_new_identity_and_keeps_the_old_one_revoked` | Anyone who can write `runs.json` can resume a run (same trust as T11) |
| T27 | A hostile upstream exposes a tool with a decoy's name to make a legitimate call trip | A decoy whose name a real tool also uses is left out of the listing, logged as `decoy.collision`, and calls to that name go to the real tool | Done | `test_a_real_tool_named_like_a_decoy_is_not_treated_as_one` | None known |
| T28 | The mail send fails, hangs or is lost at shutdown | Sending runs in the background after the run is paused; failures are logged as `notify.failed` and kept on the incident; pending sends are awaited at shutdown (up to 15 s); the incident file is the source of truth and an acknowledgement is never overwritten | Done | `test_notify`, `test_scenario_s1` | A gate killed hard (power loss) can lose an unsent email; `incidents list` still shows the incident |
| T19 | Upstream crash or error crashes the gate | Errors are logged as `gate.error`; high-impact and strict deployments return a block message | Done | covered in code paths; add fault-injection test in M2 | A crashing upstream still makes its tools fail |
| T20 | Denial of service by many concurrent calls | Not handled | Accepted for M1 | n/a | Needs rate limits (M4) |

## 6. Assumptions

- The gate host is not compromised, and its state directory is writable only by the operator and the gate.
- The operator reviews a changed definition before approving it.
- For protection against bypass, the agent has no network path except through the gate (M3).

## 7. How to keep this current

Add a row for every new attack found by the [threat watch](program/THREAT-WATCH.md), mark it Done only when a test exists, and map each control to the OWASP Top 10 for Agentic Applications (ASI01 to ASI10) when the mapping table is built in M5. Pinning and quarantine relate to tool and supply-chain risks (ASI02 and ASI04); the log relates to rogue-agent evidence (ASI10).

## 8. Review log

| Date | Reviewer | Findings | Status |
| --- | --- | --- | --- |
| 24 Oct 2026 | Author | First draft | Superseded by the next row |
| 24 Oct 2026 | Independent automated review of the M1 code (a separate reviewer with read-only access, findings then reproduced by the author) | 16 findings: 2 high, 10 medium, 4 low. Fixed in the same milestone: post-approval swap, unpinned fields, argument-type bypass of deny rules, bad regex disabling policy, narrow high-impact patterns, redaction stall, camelCase keys, missing-evidence verification, tail truncation, blind approval, forged log lines, ambiguous routing, audit-after-action, pagination loop, locking, file permissions. Claims in this document that went further than the code were corrected. Residual: unkeyed hash chain (E1-6) | Closed; awaiting community review |
| 24 Oct 2026 | Independent automated review of the M2 code (read-only reviewer, findings then reproduced by the author) | 12 findings (5 medium, 7 low) plus claims that went further than the code. Fixed in the same milestone: pause lost on restart, token smuggled in a tool name, incident text injection, hostile upstream tripping decoys, in-flight calls and duplicate incidents, token evasion (case, zero-width, base64, split values, padding), acknowledgement overwritten by a slow send, silent background failures, decoy state file permissions, event-loop blocking on resume checks, tarpit fingerprints, weak lab guard. Wording fixed in T14, T17, T24 and T26 | Closed; awaiting community review |
