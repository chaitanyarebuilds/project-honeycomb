# Direction check, 25 October 2026

We stopped after M2 to ask whether what we've built still matches what we said we'd build. Four reviewers worked separately: one compared the documents with the code feature by feature, one hunted for dead and duplicated code, one proved shorter versions of the long parts, and one tried to break the gate on a copy of the repository. This is what we took from them.

The short answer is that the direction is right, and we're not done. M0 to M2 are real, tested and honest about their limits. The "keep hostile agents out" half of the goal doesn't exist yet, because that needs identity and network enforcement, which is M3.

## Feature by feature

| Feature | Where it stands |
| --- | --- |
| F1 transport and proxy | Partly. Stdio on both sides only. Streamable HTTP isn't built. Resources and prompts aren't passed through at all, so a client can't use them via the gate. |
| F2 event log | Built: JSONL, SQLite index, redaction, hash chain, second sink, `events verify`. Not yet: a keyed chain and log rotation (backlog E1-5, E1-6). |
| F3 pinning | Built. |
| F4 policy | Allow and deny, both modes, argument matchers, fail closed. Caps, rate limits and `approve` are refused at load until M4. |
| F5 decoys | Built. They were off in the starter config, which we've fixed. |
| F6 honeytokens | Built for tool names, arguments and results. Egress scanning comes with M3. |
| F7 run identity | Not built. There's one run id per gate process and no signed token. "Revoked" means paused and retired. |
| F8 egress | Not built. No compose file, no proxy. |
| F9, F10 | Not built (M4). |
| F11 incidents | Built except escalation (M4). |
| F12 CLI | Partly. `posture`, `approvals` and `baseline` are still to come. |

## Things we've fixed because of the check

- CI only triggered on a branch called `main`, so it never ran on our branch. It runs on `chaitanyarebuilds` now.
- The README linked a LICENSE file that didn't exist. We've added the standard Apache-2.0 text.
- The starter policy still said "rules arrive in M1" and had no decoys. Fixed.
- The spec's flow section still said "session". It says "run" now. We also removed a stale line about alerts going to the console, listed `events verify`, and said plainly that Streamable HTTP and resources and prompts aren't built yet.
- We added a threat-model row for resources and prompts.
- The gate now logs `identity.issued` when it starts, not only when a run is resumed.
- Code cleanup: the five copies of "write a JSON file safely" are now one helper, the two copy-pasted honeytoken trip blocks are one function, config validation uses pydantic instead of a hand-written loop, and a few unused constants and parameters are gone. Roughly 100 lines out, about 55 in, with every test still passing.

## What the break-it tester found

It attacked a copy of the gate with damaged files, hostile input, a full disk and parallel calls. Most of it held up: 80 calls racing a trip, kill -9 and restart cycles, 16 parallel `tokens create` runs, a torn log line, oversized arguments. It also found real holes, and we fixed them:

- A honeytoken nested more than about 11 levels deep wasn't found. The scanner now has no depth limit.
- A full disk during a trip meant no pause. The run is now paused in memory first, and a failed write is cut back so it can't leave a half line that breaks the log.
- Deleting `runs.json`, `pins.json` or the log quietly undid protections. The gate now refuses to start, with a message that says what to do, and works out pauses from the log as well.
- A deny regex could be dodged by padding the value. A value too long to judge now counts as a match for deny rules.
- A huge upstream result stalled the whole gate. Results are capped, scans run off the event loop, and upstream calls time out.
- One dead upstream broke the tool list for all of them, and a damaged state file gave a raw traceback. An upstream that dies while the gate is running is now hidden on its own, and a damaged state file stops the gate at start-up with a message naming it. (An upstream that is already dead at start-up still stops the gate.)
- Smaller things: config mistakes now fail when the config loads, a symlink could smuggle a token into a git repo, and rule patterns ignore case like the high-impact list does.

One thing isn't fixed: a hung upstream process can be left running after the gate exits. It's in the threat model.

## What it means for M3

- Resources and prompts need to be handled first. Right now they're a hole we've closed only by not supporting them. They need logging and the honeytoken scan before they're switched on.
- The gate keeps its run id and pause flag per process. That works for stdio, but an HTTP gate serves many runs at once, so state has to move to the run. That's the risky part of M3 and it comes before anything else.
- The first plan put run lifetimes and the MCP config audit in M3. The check suggests moving both to M4 and keeping the agent inventory simple (a list built from what the gate has seen). We agree.
- The Docker lab has to allow the gate's hostname. The SDK's DNS-rebinding protection blocks container names by default.

## Still open from the check

- `README.md` has no quick start yet. v0.1.0 needs one an outsider can follow in 30 minutes (M5).
- `lab-run` appears in our command list but doesn't exist yet (M5).
- The backlog items for a licence and secret scan in CI (E0-4) and an MCP contract test across both spec eras (E0-5) still aren't in CI.
- A detector seam, which ADR-0001 promised, isn't there. Detection is called inline in `proxy.py`. We should either build the seam or soften the ADR when we next touch that file.
