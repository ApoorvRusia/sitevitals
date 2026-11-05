# SiteVitals — agent folder

How any agent (not just Jarvis or Clarke) picks up this project.

## What it is

SiteVitals is a fast, passive website hygiene audit: HTTPS redirect,
security headers, TLS, DNS (SPF/DMARC), scored out of 100 with a
plain-English fix per failure. v1 = URL checker (CLI). v2 adds, one PR per
change: (1) `--json` output flag, (2) repo scanning (secrets, vulnerable
deps, injection patterns), (3) web UI.

## Architecture / data contracts

- `src/checks/<id>.ts` — one file per check, filename = check id.
- `src/orchestrator.ts` — URL normalization, parallel runs, 20s timeouts.
  Returns `{ target, hostname, scannedAt, results[] }`.
- `src/scorer.ts` — weights table (tune here, not in check logic).
  Score = 100 − weights of failed checks; `error` never counts as a
  vulnerability.
- `src/report.ts` — self-contained HTML (inline CSS only).
- `src/cli.ts` — console summary + HTML report; `--json` prints pure JSON
  on stdout (`{ tool, version, target, hostname, scannedAt, score, grade,
  passed, failed, errors, results[], report }`) and still writes the HTML.
- Check result shape: `{ id, name, status: pass|fail|error,
  severity: low|medium|high, detail, fix? }`.

## How to run / test / verify

```bash
npm run build                          # compile TypeScript
node test-harness/serve.mjs            # hardened :8443, bare :8080
NODE_EXTRA_CA_CERTS=test-harness/cert.pem node dist/cli.js https://localhost:8443
NODE_EXTRA_CA_CERTS=test-harness/cert.pem node dist/cli.js https://localhost:8443 --json | jq '.score, .grade'
```

Acceptance (must hold after every change): hardened = 86/100 (B) —
8 passed, 2 failed (SPF/DMARC, honestly absent on localhost), 1 error
(no plain-HTTP listener in the harness); bare = 40/100 (F) — 2 passed,
8 failed, every finding with a fix. The cert-trust step is required:
without `NODE_EXTRA_CA_CERTS`, scores match by arithmetic but with the
wrong composition. Live-internet runs are cleanest on Apoorv's own
machine; this VM's egress blocks direct TLS probes on external targets.

## Guardrails and approval gates

- All checks are passive reads (headers, cert, DNS). No scans, no
  payloads, nothing that touches the target site.
- Work on `dev`, one PR per change, `dev` → `main`. NEVER merge:
  Clarke reviews/QAs, Apoorv approves merges.
- `error` must never be reported as a vulnerability.

## Where human decisions live

- Apoorv: merges, v2 scope calls (repo-scanning ecosystem, secrets-rule
  sources, web UI shape), and the v1 gate question.
- Clarke: PR review/QA, branch mechanics when a push fails.
