# Test report: honeycomb-gate v0.1.0 and what came after

Status: 24 to 25 October 2026. This reports what we ran, where we ran it, what passed, what failed
along the way and what we still do not know. It covers the code up to commit b2eb0de. The lab
numbers are in more detail in [LAB-RESULTS.md](LAB-RESULTS.md), and the attacks that reviewers found
are in the review log of [THREAT-MODEL.md](THREAT-MODEL.md).

## In one paragraph

All 359 automated tests pass, and the Docker lab passes all 39 of its checks, both on our machine
and in GitHub Actions. That is the good news. It is a limited kind of good news: the attacker in
every test is a script that we wrote, no real AI model has been run against the gate, the lab ran on
a Linux sandbox and not yet on Windows, and the first real email has not been sent. The review rounds
found dozens of real problems along the way (more than 70 are counted in the review log). All of those were fixed except the few listed under
"Known gaps".

## Where we tested

| Item | Value |
| --- | --- |
| Machine | Linux 6.18 sandbox in the cloud, 4 CPU cores, 15 GB of memory |
| Python | 3.13.17 (the project asks for 3.12 or newer) |
| Docker | 29.9.2, with Docker Compose |
| MCP Python SDK | `mcp` 2.3.0 |
| MCP protocol | Both 2025-11-25 (the older handshake with sessions) and 2026-07-28 (the newer one without), over stdio and over HTTP |
| Continuous integration | GitHub Actions, two jobs: `checks` (ruff, mypy, pytest) and `lab` (the Docker lab) |
| Not tested | Windows 11 with Docker Desktop and WSL 2, a real SMTP server, a real AI model, anything outside the lab |

The sandbox cannot reach mail servers and cannot push tags, so both of those are done by the owner
from his own machine.

## What the lab looks like

The agent runs in a container on an internal Docker network with no route out. It can reach only the
gate, for tools, and the egress proxy, for everything else. A second network stands in for the
internet. It holds a sink that plays the attacker's server and a partner API that is on the proxy's
allowlist. The tool servers (a customer system, a document store with one poisoned file, and a wiki)
hold made-up data only. The attacker is a script, so every run is repeatable. Nothing in the lab can
target anything outside the lab.

## Results

### The automated tests

| Check | Result |
| --- | --- |
| pytest | 359 passed in 194 seconds (353 at the last full run before the real-model agent was added; 6 new tests cover it) |
| ruff, lint and format | clean |
| mypy on `gate/src` | clean, 24 source files |
| Repository hygiene test | passes: no secrets, no tool attribution and no private email addresses in tracked files or in the last 200 commit messages |
| GitHub Actions CI | all ten most recent runs on the branch succeeded, including the latest two (8ee73bb and b2eb0de). We did not look at the two oldest runs. |

Every detection has a test with a malicious example and a benign look-alike, so false positives
are tested as seriously as detections.

### The six scenarios, Docker lab

Latest full local run: 39 of 39 checks passed. The same lab passes in CI.

| Scenario | What it tests | Result |
| --- | --- | --- |
| S0 | 50 ordinary sessions | Passed. Zero high or critical alerts and zero baseline deviations. |
| S1 | A poisoned document leads the agent to a decoy | Passed. The decoy tripped, the run was paused and its token revoked, an incident was opened, no real export happened. |
| S2 | A tool's description changes after it was trusted | Passed. The change was logged and the tool quarantined and hidden. |
| S3 | The agent tries to send a planted credential outside | Passed. The direct connection failed, the proxy refused the request, the gate paused the run, and the sink received nothing. |
| S4 | Injected requests to rotate keys, disable a user and export everything | Passed. Each call was held for approval, one of two approvals was not enough, an unanswered request timed out, the approved action ran exactly once, and the export was capped. |
| S5 | S1 again, after the incident | Passed. The learned rule matched and the document was withheld before the agent saw it. |

### The numbers

| Measure | Result |
| --- | --- |
| False positives in S0 | 0 in 50 sessions |
| Malicious step to trip, S1 | under 50 ms. The last local run printed 0.0 s, which only means the clock was too coarse to see it. |
| Sending the credential to the trip, S3 | 0.026 s in the last run. Worst case is about half a second, because the gate reads the proxy log twice a second. |
| Steps before the stop, S1 and S5 | 3 and 2 |
| Time in the tarpit, S1 | about 1.2 s (the lab sets the delay to 1 s) |
| S5 compared with S1 | one step fewer and about 1.3 s sooner. This replays identical text, so it shows the mechanism works and not that it generalises. |
| Approval requests in S4 | 4 |

Timings come from one machine and one sitting. They are not a benchmark.

## What failed, and what we did about it

We list these on purpose. Most were found by our own review rounds, where a separate reviewer and a
hostile tester each worked on the code after every milestone and we reproduced what they reported
before fixing it.

### Failures while building and running the lab

| What happened | Cause | Fix |
| --- | --- | --- |
| The very first Docker lab run failed (0 of 1 checks, "the lab ran to the end") | The document-folder helper did not create missing parent folders, so the image build broke | Fixed, and later runs passed |
| `pip` failed inside image builds in the sandbox | The sandbox's TLS certificate was not trusted in the build | A sandbox-only Dockerfile that adds the CA bundle. The repository's Dockerfile is unchanged. |
| The agent's calls to the gate went through the egress proxy | The proxy setting applied to every request | `NO_PROXY` for the gate on the agent service |
| The egress proxy could not start | It opened the token registry for writing on a read-only mount | The proxy now opens it read-only |
| The proxy was handed the gate's signing key | The lab put the key in a volume the proxy mounts | The key goes to the gate by environment only, and the proxy never holds it |
| Pushing the v0.1.0 tag was refused (HTTP 403) | The sandbox can push branches and not tags | We did not work around it. The owner published the release from the GitHub page. |
| Repeated lint failures (line too long) | `# fmt: skip` markers left over-long lines | Removed the markers and let the formatter reflow |

### Problems the reviews found in the gate itself

Each round was a separate reviewer and a hostile tester. The counts below are from the review log.

| Milestone | Found | Examples, all fixed and tested |
| --- | --- | --- |
| M1, firewall | 16 (2 high, 10 medium, 4 low) | An approved call could be swapped afterwards, the wrong argument types slipped past deny rules, a bad regex could disable a policy, forged log lines |
| M2, decoys | 12 plus claims that went further than the code | A pause was lost on restart, a token hidden in a tool name, a token disguised with case, zero-width characters, base64 or split values, incident text injection |
| M2 break-it round | 13 (5 serious) and 3 simplifications | Deep nesting, a full disk during a trip, deleted state files, a symlink hole in token placement |
| M3a, run tokens and HTTP | 19 (10 and 9) | Key rotation could overwrite the live key, a percent-encoded token got past the scan, a call that finished after its run tripped still returned real data, token signatures could be altered, deeply nested tokens gave a server error |
| M3b, egress | 6 serious | A bad log line could blind the watcher for good, a trip could be lost between reading and handling, a bare line feed could smuggle a header, a body in UTF-8 or JSON escapes hid a token, idle connections could starve the proxy |
| M4, governors | 7 | A wrong-typed argument slipped past approve rules, one person could vote twice under different spellings, rows could be hidden to dodge a cap, a slow ramp taught the baseline |
| M5, learned rules | several | Honest pages matched a rule, phrases containing links or keys could be stored, matching was fooled by markdown, accents and look-alike letters |

Where the reviewers said a claim in our own documents went further than the code did, we corrected
the document, not the claim.

## Known gaps, not fixed

These are open. Some are by design, and all of them are in the threat model.

- A hung upstream process can be left behind after the gate exits, and a hung upstream stalls every
  run that uses it.
- Traffic over HTTPS to a host that is on the allowlist is not inspected, so a credential sent that
  way goes through unseen.
- The proxy log is not rotated, so it grows without limit.
- Deny rules and pinning do not apply to resources and prompts yet. They are logged and scanned only.
- Approver names are typed by the operator, so quorum guards against a slip and not against someone
  willing to lie.
- A baseline can still drift slowly inside its anchor.
- Learned rules only stop a repeat of the same text. A reworded or split attack gets past on the
  first try.
- Inter-agent communication is not covered at all (ASI07 in the OWASP table).
- Run tokens use a symmetric key, so only the gate can check them.
- Without a closed network around the agent, the gate is advisory. The lab closes the network, and
  `honeycomb-gate posture` says plainly which level a deployment has reached.

## Not yet tested

| Item | Why | Who and how |
| --- | --- | --- |
| The real-model agent (`lab-run --agent llm`, scenarios L1 and L2) | The sandbox cannot call a model, and key creation in the Console was failing. It is tested here only against a fake model API (6 tests). | The owner, with a key in a local `.env` |
| A real incident email | The sandbox cannot reach mail servers. The notifier is tested against a fake SMTP server. | The owner runs `honeycomb-gate notify test` |
| The lab on Windows 11 with Docker Desktop and WSL 2 | We have only run it on Linux | The owner runs `uv run lab-run` and sends us the output |
| A real, adaptive attacker | Every attack so far is scripted | Outside people with the "Break it" form, and a later real-model run |
| False positives on varied real work | Fifty sessions of one kind of work say little about other work | A longer run with real agents |
| Anything outside the lab | By rule, we test only on systems the project owns | Not planned |

## What to do next

1. Run `uv run lab-run` on Windows and send us the printed result.
2. Get a model key into a local `.env` and run `uv run lab-run --agent llm`. We will add the numbers
   to LAB-RESULTS.md, whatever they show, including a model that follows the injection.
3. Rotate the mail passwords that were pasted into chat, then run `honeycomb-gate notify test`.
4. Ask outside developers to try to break it, and record what they find.
