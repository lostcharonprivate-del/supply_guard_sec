# Security Policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
(Security → Report a vulnerability). Please do not open a public issue for
anything exploitable.

Include what you sent, what happened, and what you expected. A failing test or
a manifest that reproduces the behaviour is the fastest path to a fix.

## Scope

SupplyGuard parses untrusted input by design: manifests, lockfiles, registry
configuration and GitHub Actions workflow definitions all arrive from outside.
The following are in scope and worth reporting:

- **Parser exploitation.** A manifest or lockfile that causes unbounded memory
  or CPU use, escapes the parse, or reads files outside the input set. Every
  parser is a potential entry point; `ManifestParseError` is meant to be the
  only way a malformed manifest exits.
- **Authentication and isolation.** Anything that lets one user read or modify
  another user's projects, scans or findings, or that forges a token.
- **Server-side request forgery.** A manifest or repository URL that induces a
  request to an unintended host.
- **Injection into stored findings** that executes when the dashboard renders
  it. Findings are rendered as React text nodes and never through
  `dangerouslySetInnerHTML`, so a bypass of that is a real finding.
- **Secret disclosure**, including registry credentials parsed out of a
  `.npmrc` or `pip.conf` appearing in a finding body or in logs.

## Not vulnerabilities

These are known and documented limitations, not flaws. They are stated here,
in the README threat model, and at `/api/v1/detectors` so the three cannot
drift apart:

- **Package contents are never downloaded or unpacked.** This is the largest
  gap in the tool and it is deliberate. Malicious code in a library body,
  rather than in an install hook, is invisible to every detector. Downloading
  and unpacking untrusted archives would make the scanner itself an attack
  surface, which is a worse trade for a tool meant to run in CI.
- **No reachability analysis.** A reported CVE may sit in a code path the
  project never calls. Findings say a vulnerable version is present, not that
  it is exploitable in context.
- **Detector false positives and negatives.** Each detector publishes its own
  at `/api/v1/detectors`. A heuristic firing where you would not want it is a
  tuning bug — please do open a public issue — but it is not a security
  vulnerability.

## Supported versions

The project is pre-1.0. Fixes land on the default branch; there are no
backported release branches yet.
