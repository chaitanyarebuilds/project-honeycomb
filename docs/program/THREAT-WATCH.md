# Threat and market watch

Status: process, 24 October 2026. The product is only as good as what we know about new attacks, so watching is a standing duty, not a one-off survey. What we find feeds bugs, detections and the market file.

## What we watch

| Area | Sources | Cadence | Owner |
| --- | --- | --- | --- |
| MCP spec and SDK | Releases and changelogs of `modelcontextprotocol/modelcontextprotocol` and the Python SDK; PyPI | Weekly and on each release | Platform engineer |
| Vulnerabilities in agent and MCP tooling | CVE feeds and advisories for MCP servers, SDKs and agent frameworks; CERT-In notes; vendor blogs | Weekly | Security researcher |
| Our own dependencies | Dependency and licence scans in CI | Every pull request, plus weekly full scan | Security lead |
| Attacks on agents | OWASP agentic guidance, academic papers, incident write-ups | Fortnightly | Security researcher |
| Competitors and neighbours | Releases of ContextForge and other gateways; vendor announcements; acquisitions | Fortnightly | DevRel and docs |
| Our own incidents | Event logs from the lab and pilots | Every gate | Detection engineer |

## How a finding becomes work

1. **Record** it in a dated entry in `docs/program/watch-log.md` with the source, what it means for us and a confidence level.
2. **Triage** within two working days: ignore, track, or act.
3. **Act** by opening an issue labelled `watch` with one of:
   - a **bug** against our code;
   - a **detector or test** (a new scenario with a malicious example and a benign look-alike);
   - a **design change** (needs an ADR);
   - a **docs or market update**.
4. **Close the loop** by linking the fix to the entry. Anything serious enough to affect users gets a security advisory under [SECURITY.md](../../SECURITY.md).

## Telling the team

A critical finding about our own code goes to the security lead and product owner straight away, through the private reporting process in SECURITY.md. Everything else goes into the weekly summary at the Friday review.

## Regression suite

Every real attack pattern we learn about adds one scenario to the lab (`lab/scenarios/`). The suite grows with the threat landscape, so a fix can't quietly regress.

## Safety

Watching is passive reading. We never run exploit code found online outside an isolated sandbox, never test systems we don't own, and treat everything we read as untrusted data ([DEVELOPMENT.md](../DEVELOPMENT.md), rule 6).
