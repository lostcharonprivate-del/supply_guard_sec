# SupplyGuard

Supply chain security analyzer for **npm**, **PyPI**, **RubyGems** and **Maven Central**.

It parses a project's resolved dependency tree and reports five classes of problem:
known vulnerabilities, confirmed-malicious packages, typosquats, dependency-confusion
exposure, and unmaintained dependencies — then monitors the GitHub Actions workflows
that build the project.

```bash
git clone https://github.com/lostcharonprivate-del/supply_guard_sec.git
cd supply_guard_sec
cp .env.example .env               # then edit JWT_SECRET
docker compose up --build          # open http://localhost:8000
```

or, with no infrastructure at all:

```bash
pip install -e . && supplyguard scan ./path/to/your/project
```

---

## Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Adding a fifth ecosystem](#adding-a-fifth-ecosystem)
- [**Threat model**](#threat-model) — what each detector catches, and where it fails
- [Risk scoring](#risk-scoring)
- [Validation against real incidents](#validation-against-real-incidents)
- [API](#api)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## What it does

| Detector | Catches | Source of truth |
|---|---|---|
| `vulnerability` | Known CVEs/GHSAs affecting a resolved `package@version` | OSV.dev (aggregates GitHub Advisory DB, PyPA, RustSec, …) |
| `malicious` | Packages confirmed to contain attacker-planted code | OSV `MAL-` feed (`ossf/malicious-packages`) + CWE-506/912 advisories, plus heuristics |
| `typosquat` | Names imitating popular packages | 7,962 real packages ranked by downloads, checked in |
| `dependency_confusion` | Internal names resolvable from a public registry; unclaimed namespaces; resolver configs that mix indexes | Registry configs + live registry lookups |
| `staleness` | Dependencies far behind upstream, or deprecated | Registry release history |
| CI/CD monitoring | Over-permissioned workflows, unpinned actions, script injection, secrets to unpinned actions | GitHub Actions API |

Scans run against a **fully resolved tree**, including transitive dependencies, with
each package's real depth recorded — not the flat list a manifest gives you.

---

## Quick start

### Prerequisites

| For | You need |
|---|---|
| Docker route | Docker with Compose v2 (`docker compose version`) |
| CLI / local route | Python 3.12+, and [uv](https://docs.astral.sh/uv/) or pip |
| Dashboard development | Node 22+ |

Nothing else. Postgres and Redis come from Compose; the CLI needs neither.

### Docker (everything)

```bash
cp .env.example .env
docker compose up --build
```

Brings up Postgres, Redis, the API (which also serves the dashboard) and a scan worker
on <http://localhost:8000>. Database migrations run automatically — the API container's
command is `alembic upgrade head` before `uvicorn`, so a first boot creates the schema
and later boots apply any new revisions.

The dashboard is served by the API container, so there is **one URL and no CORS to get
wrong**. Register a user at <http://localhost:8000> and you are in.

Two variables are worth setting in `.env` before you start:

- **`JWT_SECRET`** — any long random string. `openssl rand -hex 32` produces one.
  Leaving the default is fine locally and **not** fine anywhere else; see
  [Deployment](#deployment).
- **`GITHUB_TOKEN`** — optional, but unauthenticated GitHub access is capped at 60
  requests/hour, which a single repository scan can exhaust. A token raises it to
  5,000/hour and is required for private repositories and for CI monitoring.

To stop, `docker compose down`; add `-v` to discard the Postgres volume as well.

### CLI (no server, no database, no Redis)

```bash
pip install -e .

supplyguard scan ./my-project                 # scan a directory
supplyguard scan package-lock.json --tree     # one file, with the dependency tree
supplyguard scan --repo expressjs/express     # straight from GitHub
supplyguard scan . --severity high --fail-on critical   # for CI
supplyguard scan . --json > findings.json

supplyguard detectors --verbose               # every detector's known limitations
supplyguard ecosystems
```

The CLI runs the whole pipeline in-process with an in-memory cache, so it works with
nothing installed but this package. `--api-url http://localhost:8000` submits to a
running server instead.

### Local development

```bash
uv sync --extra dev                           # or: uv venv && uv pip install -e ".[dev]"
uv run pytest                                 # 247 tests, offline and deterministic
uv run pytest -m network                      # the live-API tests, opt-in

cp .env.example .env                          # then set DATABASE_URL, see below
uv run supplyguard serve                      # API on :8000
cd frontend && npm ci && npm run dev          # dashboard on :5173, proxying to :8000
```

`supplyguard serve` needs no Redis: `REDIS_URL` unset or unreachable, and the app
falls back to an in-memory cache and running scans in-process automatically. Postgres
is not optional the same way — there is no automatic fallback, so point `DATABASE_URL`
at SQLite yourself for a database-free local run:

```
DATABASE_URL=sqlite+aiosqlite:///./dev.db
```

`create_all()` runs at startup, so the file and schema are created on first boot. That
combination — SQLite plus no Redis — is the fastest way to see the thing work.

---

## Architecture

```
                  ┌──────────────┐   poll / results   ┌─────────────┐
   dashboard ────▶│  FastAPI     │◀──────────────────▶│  Postgres   │
   CLI       ────▶│  REST API    │                    └─────────────┘
                  └──────┬───────┘
                         │ enqueue                    ┌─────────────┐
                         ▼                            │   Redis     │
                  ┌──────────────┐  ◀─── cache ──────▶│ queue+cache │
                  │ arq worker   │                    └─────────────┘
                  └──────┬───────┘
                         │
                  ┌──────▼────────────────────────────────────────┐
                  │                  Scanner                      │
                  │  routes files ▸ parses ▸ runs detectors ▸ scores│
                  └──────┬──────────────────────┬─────────────────┘
                         │                      │
          ┌──────────────▼───────┐   ┌──────────▼─────────────┐
          │  Ecosystem adapters  │   │   Detection engines    │
          │  npm · pypi          │   │  vulnerability         │
          │  rubygems · maven    │   │  malicious             │
          │  (plugin interface)  │   │  typosquat             │
          └──────────────────────┘   │  dependency_confusion  │
                                     │  staleness             │
                                     └────────────────────────┘
```

Two plugin seams do the structural work:

**`EcosystemAdapter`** — how to parse a lockfile and query a registry. Every adapter
normalises its registry's idiosyncratic JSON onto one `PackageMetadata` shape, so no
detector contains an `if ecosystem == "npm"` branch.

**`Detector`** — consumes a `ScanContext`, returns `Finding`s. Detectors never touch
the database, never know about each other, and each one's failure is contained: a
registry outage during malicious-package heuristics still leaves the CVE results intact.

Both are pure enough to test without a network. `core/types.py` imports nothing from
FastAPI, SQLAlchemy or httpx, which is what keeps that true.

### Two things worth looking at

**npm lockfile depth.** npm hoists packages to the top of `node_modules` regardless of
where they sit in the dependency graph, so path nesting is not depth. The parser
implements npm's actual resolution — walking up the `node_modules` chain from the
requiring package — and then does a BFS from the root, so `accepts` shows as depth 1
under `express` even though it is installed at `node_modules/accepts`.

**Advisory branch selection.** `minimist`'s GHSA-vh95-rmgr-6w4m is fixed in 0.2.1 on
the 0.x branch and 1.2.3 on the 1.x branch. Taking `affected[0]` would tell a user on
1.2.0 to install 0.2.1 — a downgrade into a different vulnerability. The scanner picks
the branch whose range actually contains the scanned version.

---

## Adding a fifth ecosystem

One file, one decorator. Nothing in the core, the detectors, the API or the dashboard
changes:

```python
# src/supplyguard/ecosystems/cargo.py
@register
class CargoAdapter(EcosystemAdapter):
    name = "cargo"
    display_name = "crates.io (Rust)"
    osv_ecosystem = "crates.io"
    ghsa_ecosystem = "RUST"
    manifest_patterns = ("Cargo.lock", "Cargo.toml")
    lockfile_patterns = ("Cargo.lock",)

    def parse_manifest(self, content, filename) -> DependencyGraph: ...
    async def fetch_metadata(self, name, http) -> PackageMetadata: ...
    def registry_package_url(self, name) -> str: ...
    def parse_version(self, version) -> tuple: ...
```

Then `python scripts/refresh_reference_sets.py --ecosystem cargo` to build its
typosquat reference set. The adapter is discovered automatically.

---

## Threat model

Every detector here is a heuristic against an adversary who can read its source. This
section states what each one actually catches and, more importantly, what it does not —
a finding you cannot calibrate is a finding you cannot act on.

The same text is served at `GET /api/v1/detectors` and shown in the dashboard next to
the findings, so what a user reads can never drift from what the code does.

### Scope

**In scope.** Dependency manifests and lockfiles, registry metadata, public
vulnerability databases, and GitHub Actions workflow definitions and run history.

**Out of scope, deliberately.**

- **Package contents are never downloaded or unpacked.** SupplyGuard analyses metadata
  and registry-exposed install scripts only. Executing or even unpacking untrusted
  archives is a meaningfully larger security problem than the one being solved, and
  doing it badly would make the scanner itself an attack surface. The cost is stated
  plainly under each detector.
- **No reachability analysis.** A CVE in a code path you never call is reported the
  same as one you do.
- **No build reproduction.** Maven's transitive closure is resolved at build time from
  each dependency's POM; SupplyGuard reports the declared layer and says so.

### `vulnerability` — known CVEs

Cross-references every resolved `package@version` against OSV.dev, which aggregates the
GitHub Advisory Database, PyPA, RustSec, Go and others. OSV performs the affected-range
matching server-side, which is why this project does not reimplement four ecosystems'
range semantics — that would be a rich source of silent false negatives.

**False positives**
- No reachability analysis: an advisory in a package whose vulnerable function you never
  call is reported identically to an exploitable one.
- Dev-only dependencies are reported but weighted down; many never ship to production.
- Distribution-patched builds with backported fixes are invisible to OSV, so a
  vendored-and-patched copy can still be flagged.

When a GitHub token is configured, advisories that OSV publishes without a CVSS
vector are cross-checked against the GitHub Advisory Database for a numeric score.
This corroborates severity only — it never adds or removes a finding, since OSV
already aggregates GHSA. Without a token the step is skipped and the scan says so.
Sonatype OSS Index and deps.dev are not integrated.

**False negatives**
- Only advisories already published *and* mapped to a package range are found. A
  disclosed-but-unindexed vulnerability is missed.
- Unpinned manifests (`package.json`, plain `pyproject.toml`) resolve to an approximate
  version, so matching may not reflect what actually installs. Upload a lockfile.
- Vendored or bundled code that is not a declared dependency is invisible.

### `malicious` — confirmed-malicious packages

Two layers. First, known-bad intelligence: OSV republishes `ossf/malicious-packages`
under `MAL-` identifiers, and the GitHub Advisory Database tags planted code with
**CWE-506** (Embedded Malicious Code) and **CWE-912** (Hidden Functionality). Both
`event-stream@3.3.6` and `ua-parser-js@0.7.29` are GHSA entries carrying CWE-506 — so
without that check they would be reported as ordinary CVEs rather than compromises.

Second, heuristics for packages nobody has reported yet: recent publication, negligible
downloads, no repository or a mismatched one, minimal README, a release after years of
dormancy (the maintainer-takeover profile), and static analysis of install-time scripts.
Each signal is individually weak, so they are combined with saturating arithmetic and
only reported once enough independent signals agree. The exception is install-script
analysis: a `postinstall` that pipes a download into a shell needs no corroboration.

**False positives**
- New, small or internal packages legitimately have few downloads, no README and no
  linked repository. Several signals must agree, but a genuinely obscure package can
  still cross the threshold.
- Native modules must run code at install time. `node-gyp rebuild`, `husky install` and
  `prebuild-install` are allowlisted; unusual build wrappers are not.
- A long-dormant package receiving a legitimate revival release matches the takeover
  profile exactly.

**False negatives**
- **Package contents are never inspected.** Malicious code in the library body rather
  than an install hook is completely invisible here. This is the single largest gap in
  the tool, and it is a deliberate scope decision, not an oversight.
- A patient attacker who writes a plausible README, links a real repository and waits
  out the age threshold defeats every heuristic.
- The `MAL-` feed only covers packages already reported and reviewed — always after
  the fact, and after some number of installs.

### `typosquat` — name imitation

Compares every dependency against the most-downloaded packages in its ecosystem using
independent signals rather than edit distance alone: bounded Levenshtein, Damerau
transposition, QWERTY adjacency, Unicode confusables, ASCII lookalikes (`rn`/`m`,
`I`/`l`/`1`, `0`/`o`), separator swaps, singular/plural, scoped-versus-unscoped
confusion, regional spelling, digit insertion, and affix padding.

Edit distance alone is a poor detector: `react` and `preact` are one character apart
and both legitimate, while `electorn`/`electron` is a transposition that reads almost
identically. So a finding requires **both** a similarity signal **and** corroboration —
the candidate itself being obscure by download count or age. The decisive guard is that
a package which is *itself* in the reference set is never flagged, which is what keeps
`preact` quiet.

**False positives**
- Legitimate ecosystem ports and companions genuinely resemble what they complement
  (`django-redis` vs `redis`), which is why the affix signal is deliberately weak.
- A new, low-download internal package whose name sits near a popular one is flagged
  until it accrues downloads.
- Maven Central publishes no download statistics, so corroboration there falls back to
  publication age alone and is weaker.

**False negatives**
- The reference set is the top ~2,000 packages per ecosystem. A squat of a moderately
  popular package is missed — `mongoose` and `babel-cli` are both outside npm's
  top 2,000 by download count, so squats of them would not be caught.
- A squat with no popular counterpart — a plausible-sounding invented name — is out of
  scope here; that is what the malicious heuristics are for.
- A long-running campaign that has accumulated real downloads fails the corroboration
  step.

### `dependency_confusion` — resolution hijacking

Alex Birsan's 2021 research and the 2022 PyTorch `torchtriton` compromise both exploit
the same thing: a build that resolves a name from more than one source, where the public
registry wins. Three distinct findings, because the remediation differs:

1. **A resolver config that mixes indexes.** pip does not treat indexes as a priority
   list — it queries all of them and installs the highest version found anywhere. A
   public `extra-index-url` alongside a private `index-url` is a standing exposure even
   when nothing is currently being shadowed. This is the one worth fixing first: it
   closes the whole class.
2. **An unreserved private namespace.** If `@yourorg` is routed privately but unclaimed
   publicly, anyone can register it. Claiming it costs nothing and removes the attack.
3. **An internal name that exists publicly.** Reported at critical when the public
   package also publishes the exact version you resolved.

**False positives**
- A company that deliberately mirrors its own package publicly is flagged; the tool
  cannot distinguish an intentional release from a shadowing one.
- Name-convention heuristics are inference, not evidence. `internal-slot` is a top-2000
  npm package whose name starts with "internal" — it is excluded by checking candidates
  against the popular-package reference set, but the general failure mode remains.
  Configure `organization_scopes` explicitly to remove the guesswork.

**False negatives**
- Without a registry config file, internal packages that follow no naming convention are
  indistinguishable from public ones.
- Resolution order also depends on CI environment variables and CLI flags that are not
  visible in the uploaded files.
- This is a point-in-time check, not monitoring. A public package published the day
  after a scan closes the window silently.

### `staleness` — unmaintained dependencies

Not a vulnerability today; a predictor. Stale packages are where the next unpatchable
CVE lands, and an abandoned package whose maintainer will gratefully accept help is
exactly what a takeover attacker looks for.

**False positives**
- Small, complete libraries legitimately stop changing.
- A deliberate major-version pin looks identical to neglect from the registry's side.

**False negatives**
- A package receiving cosmetic releases looks maintained even when its security posture
  is not.
- A fork that has silently become the real upstream is not detected.

### CI/CD monitoring

Workflow files are the most privileged code in a repository: they run on every push,
hold the repository's secrets, and routinely execute third-party code pinned to a
mutable tag. Checks are limited to those with a defensible rule behind them:

| Rule | Why it matters |
|---|---|
| `permissions: write-all` | Any compromised dependency or action in the workflow can push commits, publish releases or alter branch protection. |
| Action not pinned to a commit SHA | A tag is a mutable pointer. This is how the `tj-actions/changed-files` compromise reached tens of thousands of repositories in March 2025. |
| Secrets passed to an unpinned third-party action | The secret goes to whatever code the reference points at on the day the workflow runs. |
| Script injection | `${{ github.event.issue.title }}` inside `run:` is substituted before the shell sees it, so a crafted title executes on the runner. |
| Privileged triggers | `pull_request_target` runs with the base repo's secrets against code the submitter controls. |
| Suspicious run steps | Fetching and executing remote scripts during a build defeats every dependency pin in the repository. |
| Workflow + manifest changed in one commit | How a malicious dependency gets reviewed as a build tweak. Also completely normal maintenance — reported as *read this diff*, not as an attack. |

**Limitations.** Build *logs* are not ingested, so runtime network egress is not
observed — only what the workflow definition declares. Self-hosted runner configuration
is invisible. GitLab CI is not implemented.

### The tool's own attack surface

SupplyGuard parses attacker-influenced input (manifests, registry JSON, workflow YAML)
and makes outbound requests. Accordingly: all parsing is pure-Python with no `eval` and
no shell; YAML is `safe_load` only; the container runs as an unprivileged user; the SPA
file handler resolves paths and rejects anything outside the build directory; findings
render as React text nodes, never `dangerouslySetInnerHTML`; and login compares against
a dummy hash when the account does not exist so timing does not disclose which emails
are registered. Project ownership violations return 404 rather than 403, since
confirming an id exists would leak the existence of other users' projects.

---

## Risk scoring

A finding count is not a risk assessment. Two projects can each have "12 vulnerabilities"
where one has a critical RCE in a direct production dependency and the other has twelve
low-severity issues six levels deep in a dev-only tree.

```
risk = severity × exploitability × depth × confidence × category
```

- **severity** — from the CVSS base score, computed locally from the vector so that it
  is comparable across sources that report scores, labels or nothing.
- **exploitability** — derived from the CVSS *vector*, not invented. Network-reachable,
  no privileges, no user interaction is what actually gets exploited; local access
  needing high privileges and user interaction rarely does.
- **depth** — `1/(1 + 0.35 × depth)`. A direct dependency is both more reachable and
  immediately actionable.
- **confidence** — heuristic findings are discounted so a probable typosquat never
  outweighs a confirmed CVE.
- **category** — a confirmed-malicious package is strictly worse than a CVE of equal
  nominal severity; staleness is weighted far below both.

Per-finding risks combine through a saturating curve, so volume matters without letting
a long tail of low-severity noise pin a project at 100. Dev-only findings are discounted
to 45% — not excluded, because a compromised build tool still runs on developer machines
and CI.

**One override:** any confirmed-malicious package floors the score at 75 (grade F)
regardless of the arithmetic. Attacker code in the tree has already executed at install
time. That is an incident, not a point on a curve.

Grades: **A** < 10, **B** < 25, **C** < 45, **D** < 70, **F** ≥ 70.

---

## Validation against real incidents

Detectors are tested against documented attacks with known ground truth, paired with the
legitimate packages that must stay quiet — a detector that fires on everything is not a
detector.

| Incident | Detected as | Test |
|---|---|---|
| `event-stream@3.3.6` (2018) | malicious — CWE-506 | `test_scanner.py` |
| `ua-parser-js@0.7.29` (2021) | malicious — CWE-506/912 | `test_scanner.py` |
| `crossenv` vs `cross-env` (npm, 2017) | typosquat — separator swap | `test_similarity.py` |
| `colourama` vs `colorama` (PyPI, 2018) | typosquat — regional spelling | `test_similarity.py` |
| `jeIlyfish` vs `jellyfish` (PyPI, 2019) | typosquat — ASCII lookalike (`I`/`l`) | `test_similarity.py` |
| `python3-dateutil` vs `python-dateutil` (2019) | typosquat — digit variant | `test_similarity.py` |
| `reqeusts` vs `requests` | typosquat — transposition | `test_similarity.py` |
| `torchtriton` shape (PyTorch, 2022) | dependency confusion — mixed indexes | `test_detectors.py` |
| Birsan-style unclaimed scope (2021) | dependency confusion — unreserved namespace | `test_detectors.py` |

**Must not fire:** `react`/`preact`, `cross-env`, `urllib3`, `colorama`, `jellyfish`,
`python-dateutil`, `boto3`, `django-redis`, `internal-slot`, and ordinary install hooks
(`node-gyp rebuild`, `husky install`, `prebuild-install || node-gyp rebuild`).

CI monitoring was checked against three genuinely hardened repositories — `psf/requests`,
`pallets/flask` and `expressjs/express`, all SHA-pinned with explicit `permissions` —
which produce **zero** findings, and against a deliberately weak workflow, which produces
six.

---

## API

`GET /docs` for the interactive OpenAPI reference. Auth is JWT bearer; GitHub OAuth is
supported when configured.

```
POST   /api/v1/auth/register                  POST /api/v1/auth/login
POST   /api/v1/scans                          submit a scan, returns an id immediately
GET    /api/v1/scans/{id}                     poll; filter by ?severity= and ?category=
GET    /api/v1/scans/{id}/tree                dependency tree with findings overlaid
GET    /api/v1/projects/{id}/trend            risk score over time
POST   /api/v1/projects/{id}/ci/scan          analyse GitHub Actions
GET    /api/v1/projects/{id}/ci/events        CI timeline
GET    /api/v1/detectors                      every detector's documented limitations
GET    /api/v1/ecosystems
```

Scans return `202` with a scan id and run in the background — a full tree against
several external APIs takes far longer than a request should. The worker runs on Redis
via arq when available and falls back to an in-process task otherwise, so the API is
usable with nothing but a database.

### Caching and rate limits

Every external call goes through one client so that caching, throttling, retries and
metrics cannot be forgotten at a call site. Per-host token buckets, 24h TTL on package
metadata, 6h on advisories, and negative caching for 404s — re-asking a registry about
a package that does not exist is the most common wasted call. OSV lookups are batched:
a 250-package lockfile sharing 30 advisories costs ~2 batch calls plus 30 cached
document fetches, not 250 queries.

---

## Deployment

Compose as shipped is a **working local stack, not a production deployment**. It uses
a default database password, publishes no TLS, and defaults `ENVIRONMENT` to
`development`. What follows is the gap between the two.

### 1. Set the secrets

```bash
JWT_SECRET=$(openssl rand -hex 32)     # anything long and random
ENVIRONMENT=production
DATABASE_URL=postgresql+asyncpg://USER:STRONG_PASSWORD@HOST:5432/supplyguard
REDIS_URL=redis://HOST:6379/0
GITHUB_TOKEN=ghp_...                   # 60 -> 5,000 requests/hour
CORS_ORIGINS=https://supplyguard.example.com
```

With `ENVIRONMENT=production` the app checks its own configuration at startup and logs

```
INSECURE CONFIGURATION: JWT_SECRET is still the default value.
```

for a default secret, an enabled `DEBUG`, or a `*` in `CORS_ORIGINS`. **These are
warnings, not refusals** — the app boots anyway, because refusing to start is worse in
a demo environment. Nothing enforces this for you, so grep your startup logs for
`INSECURE CONFIGURATION` and treat a hit as a failed deploy.

Changing `JWT_SECRET` invalidates every issued token; users log in again.

### 2. Run the migrations

The API container runs `alembic upgrade head` on boot, so Compose needs nothing extra.
Running the API another way means running migrations yourself first:

```bash
alembic upgrade head
```

`create_all()` also runs at startup as a convenience for a first local boot. Alembic is
what a real deployment should rely on — it is the only path that handles a schema
change to an existing database.

### 3. Scale the worker, or do not

The `worker` service runs scans through Redis via arq. If it is absent or Redis is
unreachable, the API runs scans **in-process instead** and the stack still works. That
fallback is a convenience for small installs, not a scaling strategy: in-process scans
compete with request handling. Run the worker in anything with real traffic, and scale
it independently — scan cost tracks dependency-tree size, request cost does not.

```bash
docker compose up --scale worker=3
```

### 4. Put TLS in front

The API speaks plain HTTP and does not terminate TLS. Run it behind a reverse proxy or
ingress that does, and point `CORS_ORIGINS` at the public origin. JWTs travel in the
`Authorization` header — over plain HTTP on an untrusted network they are readable.

### 5. Harden Postgres

The Compose Postgres uses `supplyguard:supplyguard` and is deliberately not published
outside the Compose network (`expose`, not `ports`). A managed database with a real
password and network policy is the production answer. The database holds password
hashes and every scan result, so it is worth the same care as the application.

### Deployment checklist

- [ ] `JWT_SECRET` is a long random value, not the default
- [ ] `ENVIRONMENT=production`, and startup logs contain no `INSECURE CONFIGURATION`
- [ ] `DATABASE_URL` points at a database with a real password
- [ ] `alembic upgrade head` has run against it
- [ ] `CORS_ORIGINS` lists your real origin, no `*`
- [ ] TLS terminates in front of the API
- [ ] `GITHUB_TOKEN` is set, or you accept 60 GitHub requests/hour
- [ ] The `worker` service is running

### Health check

`GET /health` returns 200 with the supported ecosystems, and is what the container's
`HEALTHCHECK` polls. It does not touch the database: a 200 means the process is up, not
that Postgres is reachable. If the database is down the API still starts, and every
persistent endpoint fails — that is logged loudly at startup.

---

## Troubleshooting

**Every GitHub call fails, or CI monitoring returns 502.** Unauthenticated GitHub
access is 60 requests/hour and one repository scan can spend it. Set `GITHUB_TOKEN`.
A failed CI analysis returns **502 with the reason**, never an empty timeline — an
empty list would read as "your pipeline is clean" when the truth is "nothing was
examined."

**A scan sits at `queued` forever.** The worker is not running and Redis is
unreachable, so nothing picked the job up. Either start the worker, or clear
`REDIS_URL` to force the in-process path. A scan that is genuinely running reports
`running`, not `queued` — the two are distinguishable on purpose.

**`docker compose up` fails on the frontend build.** The image builds the dashboard
with `npm ci`, which fails if `frontend/package.json` and `frontend/package-lock.json`
have drifted. Run `npm install` in `frontend/` and commit the updated lockfile.

**Port 8000 is already in use.** Change the published port in `docker-compose.yml`
(`"8080:8000"`) and add the new origin to `CORS_ORIGINS`.

**The dashboard loads but every request 401s.** The token expired — the default is 12
hours (`JWT_EXPIRY_MINUTES`). Log in again. If it persists, `JWT_SECRET` changed
between issuing and verifying, which invalidates every existing token.

**Scans are slow.** The first scan of a tree is uncached and does real network work
against OSV and the registries. Package metadata is cached 24h and advisories 6h, so a
rescan is dramatically faster. Without Redis the cache is per-process and dies with it.

---

## Development

```
.github/workflows/ci.yml   lint, type-check, test, and build the Docker image
data/reference-sets/       7,962 popular packages, checked in, for typosquat checks
frontend/                  React dashboard (Vite + TypeScript)
migrations/                Alembic revisions
scripts/                   reference-set refresh
src/supplyguard/
  core/          types, CVSS scoring, risk model   — no framework imports
  ecosystems/    adapter interface + npm, pypi, rubygems, maven
  detectors/     detector interface + 5 engines, similarity primitives
  clients/       cached rate-limited HTTP, OSV, GitHub, cache backends
  ci/            GitHub Actions analysis and monitoring
  api/           FastAPI routes, schemas, auth
  db/            SQLAlchemy models, session management
  jobs/          arq worker and queue
  scanner.py     orchestration          cli.py   command line
tests/
  unit/          detector, parser and scoring behaviour
  integration/   API and end-to-end scanner tests
  fixtures/      real lockfiles, not hand-written samples
```

```bash
uv run pytest                  # 247 tests, offline and deterministic
uv run pytest -m network       # live-API tests, opt-in
uv run ruff check .
uv run mypy src
uv run python scripts/refresh_reference_sets.py   # rebuild typosquat reference sets
```

CI runs exactly these, plus the dashboard build and a Docker image build, on every push
and pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for what a good change looks
like, and [SECURITY.md](SECURITY.md) for how to report a vulnerability.

Tests are offline by default so the suite does not fail because a registry is slow or an
advisory was republished. Parsers are exercised against a real 244-entry npm lockfile
rather than a hand-written sample, because hoisting and dev-flag propagation only
misbehave at that scale.

## License

MIT — see [LICENSE](LICENSE).
