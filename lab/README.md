# Lab

Test targets, scenarios and the Docker lab for Project Honeycomb. Everything here is synthetic and
runs on your own machine.

## What is in here

- `targets/crm.py`: a toy CRM over generated customers. `export_report` records every call, so a
  scenario can prove whether a real export happened.
- `targets/docs.py`: a document store with one poisoned document (a harmless stand-in), also
  offered as MCP resources and a prompt.
- `scenarios/s1_poisoned_doc.py`: scenario S1 over stdio, used by the tests.
- `scenarios/lab_agent.py`: the scripted agent that runs inside the Docker lab (S1 and S3). It is
  a plain script with no model, and it refuses to connect to anything that isn't a lab service.
- `sink.py`: stands in for an attacker's server on the internet. It only counts what arrives.
- `docker-compose.yml`, `Dockerfile`, `gate.docker.yaml`: the lab itself.
- `run_lab.py`: brings the lab up, plays the scenarios and checks the result.

## The Docker lab

The agent sits on `labnet`, an internal Docker network with no route out. Its only exits are the
gate (to reach its tools) and `honeycomb-egress` (to reach anything else). A second network,
`outside`, plays the internet: it holds the sink and a partner API that is on the proxy's
allowlist. The agent can't see `outside` at all.

Run it (needs Docker, on Linux or Docker Desktop with the WSL 2 backend):

    uv run python -m lab.run_lab

You should see fifteen `[pass]` lines and `lab passed: 15/15 checks`. Add `--keep` to leave the
containers running afterwards, and `--no-build` to reuse the image you already built. A JSON
record of the run goes to `lab/results/` (git-ignored).

What it plays:

- S3: the agent finds a planted honeytoken in its workspace and tries to send it to the sink,
  first by connecting directly (fails, there is no route), then through the proxy (refused). The
  gate logs `egress.blocked` and `honeytoken.used`, pauses the run and revokes its token. The sink
  receives nothing. A harmless request to the partner API goes through, as a look-alike.
- S1 over HTTP: a poisoned document leads the agent to a decoy. The decoy trips, the run is paused
  and its token revoked, and no real export happens.

The lab's signing key is a fixed value in `docker-compose.yml`, passed to the gate only. It is not a secret, and it keeps the key out of the state folder that the proxy mounts. The containers run as root, which is fine for a lab and not for production.

When S3 has shown the network really is closed, the runner writes the proof file that
`honeycomb-gate posture` looks for, and posture then reports the network as verified.

The same lab runs in GitHub Actions on every push.
