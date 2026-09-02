# Contributing

## Setup

```bash
uv sync --extra dev              # Python deps
cd frontend && npm ci && cd ..   # dashboard deps
```

## The checks CI runs

Run these before opening a pull request; `.github/workflows/ci.yml` runs the
same three jobs.

```bash
uv run ruff check .
uv run mypy src
uv run pytest -q                 # network tests excluded by default
```

```bash
cd frontend && npm run lint && npm run build
```

Network tests hit OSV, the package registries and GitHub. They are opt-in so
the suite stays deterministic:

```bash
uv run pytest -m network
```

## What a good change looks like

**A detector change needs a test that states the case in its name.** The test
suite is written so the names read as claims about behaviour —
`test_a_popular_public_package_is_not_treated_as_internal` says what the
system does. Follow that.

**False positives are bugs, and they are the expensive kind.** A tool that
cries wolf gets muted, and a muted tool detects nothing. Most of the existing
tests exist because a heuristic fired somewhere it should not have: a top-2000
npm package flagged as an internal name, 89 findings on normal build steps
because an entropy threshold tuned for one-line install hooks met a multi-line
shell script. When you add a signal, add the negative case that proves it stays
quiet.

**Every detector must state its own limitations.** `Detector.describe()` feeds
`/api/v1/detectors` and the dashboard, and
`tests/integration/test_api.py::TestMeta` asserts that each one is populated. A
new detector without documented false positives and negatives will fail CI —
this is deliberate, so what a user reads cannot drift from what the code does.

**Do not add package-content inspection without discussing it first.** Not
downloading or unpacking package archives is a scope decision, documented in
[SECURITY.md](SECURITY.md) and the README threat model. Changing it changes the
tool's attack surface.

## Adding an ecosystem

Subclass `EcosystemAdapter` in `src/supplyguard/ecosystems/` and decorate it
with `@register`. The base class in `ecosystems/base.py` documents each method.
The adapter is the only place that should know about a registry's API shape.

## Adding a detector

Subclass `Detector` in `src/supplyguard/detectors/` and decorate it with
`@register_detector`. A detector consumes a `ScanContext` and returns
`Finding`s; it must not raise on bad data — `safe_detect` converts a failure
into a note so that one detector failing does not abort a scan.

## Style

Ruff enforces the rules; `line-length` is 100. Comments should explain why a
decision was made, not restate what the line does. The existing code holds to
this fairly closely — match it.
