# Releasing

How a version of the gate is cut. The checks run on their own. The two steps that publish
something outside the repository need an account, so a person does those.

## What CI does

Every push to `chaitanyarebuilds` runs ruff, mypy and the tests, and plays the Docker lab. A tag
that starts with `v` also builds the wheel and the container image and keeps them as build
artifacts (`.github/workflows/release.yml`). It does not publish them.

## Before you tag

1. The latest commit on the branch has a green CI run, both jobs.
2. `CHANGELOG.md` says what is in the version and what is still missing.
3. `docs/LAB-RESULTS.md` matches a recent `uv run lab-run`.
4. The threat model's known gaps are still the ones the code has.

## Tagging

    git tag -a v0.1.0 -m "v0.1.0: the first public build of the Phase 0 gate"
    git push origin v0.1.0

## If the tag could not be pushed

The build sandbox the first release was prepared in can push to the branch but not tags (the remote
answers 403). In that case create the tag from a machine that can, on the commit CI passed:

    git fetch origin
    git tag -a v0.1.0 8132388 -m "v0.1.0: the first public build of the Phase 0 gate"
    git push origin v0.1.0

Or make a release in the GitHub web page: pick the tag name `v0.1.0`, target that commit, and
publish. Either way the release workflow starts on its own.

## Publishing, by a person

- **PyPI.** Create the `honeycomb-gate` project and add this repository as a trusted publisher
  (no token needed), then upload the wheel from the release workflow's artifacts. Check the wheel
  first: `unzip -l` it and look for anything that is not source (no `.env`, no state folder, no
  notes). The project name is claimed on first upload and cannot be taken back, so decide it first.
- **Container image.** Push the image from the same run to a registry you own. The image runs as a
  non-root user and keeps state in `/state`, so mount a volume there.

Both are left to a person on purpose: they are public, they carry the project's name, and they are
hard to undo.
