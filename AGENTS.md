# SiteVitals — instructions for AI agents

You are an AI agent (Claude, Copilot, Muse, Grok, or similar). A human gave
you this repository's URL so you can run SiteVitals on their website or
project. This file is everything you need. Deeper project context lives in
`agent/AGENTS.md`.

## What SiteVitals does

A passive security hygiene audit with two modes:

- **URL mode** — audits a website (HTTPS, security headers, cookie flags,
  TLS, DNS) and scores it /100 with a plain-English fix per failure.
- **Repo mode** — audits a local working tree (leaked secrets, vulnerable
  dependencies, injection patterns, Dockerfile, license audit, CI config)
  with its own /100 score, plus a CycloneDX SBOM export.

## Install (once)

```bash
git clone https://github.com/ApoorvRusia/sitevitals.git
cd sitevitals
npm install
npm run build
```

## Run

```bash
# Audit a website (JSON on stdout, HTML report written to reports/)
node dist/cli.js https://example.com --json

# Audit a local repo
node dist/cli.js repo /path/to/project --json

# SBOM inventory (no scoring)
node dist/cli.js repo /path/to/project --sbom
```

Always use `--json` when you are the consumer: stdout is pure JSON matching
`schemas/url-report.schema.json` or `schemas/repo-report.schema.json`.
`sitevitals.tool.json` is the machine-readable tool manifest (commands,
flags, schemas, exit codes).

## Exit codes (gate on these)

| Code | Meaning |
|------|---------|
| 0 | Scan completed, score >= `--min-score` (default 70) |
| 1 | Scan completed, score < `--min-score` |
| 2 | Usage/runtime error — no score produced |

Use `--min-score <n>` to set your own pass bar (0–100).

## How to report back to your human

1. Lead with the score and grade.
2. List every `fail` result with its `detail` and `fix` — the fix text is
   written for humans; pass it through.
3. Treat `error` results as "could not check", never as vulnerabilities.
4. Mention the HTML report path (`report` field) so the human can open it.

## Safety rules (do not break these)

- **Report-only.** SiteVitals never modifies the scanned site or repo.
  Do not add auto-fix behavior on top of it without explicit human approval.
- **Secrets are never printed and never verified live.** Findings carry a
  rule id, file, line, and a redacted preview only. Never try a found
  secret against a service to "check if it's real".
- **Data boundary:** the only data that leaves the machine is package
  names + versions, sent to the OSV.dev API for the dependency check.
  No code, no file contents, no secrets.
- **Allowlist:** a `.sitevitals-allowlist.json` in the scanned repo root
  suppresses known-fake findings (test fixtures). Respect it; suggest
  additions only with a reason per entry.
- All URL checks are passive reads (headers, cert, DNS). No scans, no
  payloads. It is safe to run against any site your human owns or is
  authorized to check.

## Limits

SiteVitals is a hygiene check, not a penetration test. It will not find
application vulnerabilities. Say so when you summarize results.
