# SiteVitals — agent folder

I keep this folder so any agent can pick up this project cold and work
on it the way I want it worked on. No prior context is assumed.

## What it is

SiteVitals is a fast, passive website hygiene audit: HTTPS redirect,
security headers, TLS, DNS (SPF/DMARC), scored out of 100 with a
plain-English fix per failure. v1 = URL checker (CLI). v2 adds, one PR per
change: (1) `--json` output flag, (2) repo scanning (secrets, vulnerable
deps, injection patterns), (3) web UI. Extra URL checks land one per PR
after repo scanning: cookie flags, Permissions-Policy, isolation headers,
CAA, security.txt, cert expiry window, HSTS preload.

## Architecture / data contracts

- `src/checks/` — four grouped files, NOT one per check id: `dns.ts`
  (SPF/DMARC), `headers.ts` (HSTS, CSP, framing, nosniff,
  referrer-policy, version-leak, cookie flags), `https.ts` (redirect),
  `tls.ts` (certificate, TLS version).
- `src/repo/` — repo scanning (`repo` subcommand): `scanner.ts` (tree
  walk + caps), `orchestrator.ts`, `scorer.ts` (repo weights), `report.ts`,
  `allowlist.ts`, `checks/` (one module per area: secrets, deps, injection).
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
10 passed, 2 failed (SPF/DMARC, honestly absent on localhost), 1 error
(no plain-HTTP listener in the harness); bare = 31/100 (F) — 2 passed,
10 failed (the previous 9 plus `permissions-policy`), every finding with
a fix. The cert-trust step is required:
without `NODE_EXTRA_CA_CERTS`, scores match by arithmetic but with the
wrong composition. I run live-internet checks on my own machine;
sandboxed environments may block direct TLS probes on external targets.

Repo scanning:

```bash
node dist/cli.js repo test-harness/fixtures/clean --json | jq '.score, .grade'
node dist/cli.js repo test-harness/fixtures/dirty --json | jq '.score, .grade'
node dist/cli.js repo .   # dogfood: must be 0 findings (root allowlist covers the test-harness key + planted fixture secrets)
```

Acceptance (repo): clean fixture = 100/100 (A), zero findings; dirty
fixture flags every plant (secrets + vulnerable lodash + every injection
pattern); dogfood on this repo = 0 findings; reports never print a secret
value (rule id + file + line + redacted preview only); found secrets are
never verified live. Secrets rules are the vendored Gitleaks defaults
(`src/repo/rules/secrets.json`, MIT, attributed) — 13 rules: AWS access
+ secret key, GitHub PAT, GitLab PAT, Slack token + webhook, Stripe
secret, private key, JWT, npm token, SendGrid key, generic API key,
generic password. Deps (npm first): `package-lock.json` is parsed and
checked against OSV.dev in two steps (`POST /v1/querybatch` for minimal
records, then `GET /v1/vulns/<id>` for aliases/severity/fixed versions);
only names + versions leave the machine. `--osv-fixture` runs the deps
check against recorded responses — `osv-lodash-vulnerable-response.json`
(lodash 4.17.11 → GHSA-35jh-r3h4-6jhm (CVE-2021-23337) + GHSA-p6mc-m468-83gw (CVE-2020-8203), fix 4.17.21)
and `osv-lodash-clean-response.json` (lodash 4.17.21 → clean); both are
hand-recorded from live OSV responses fetched 2026-11-24
(the fixture is a `{querybatch, details}` wrapper covering both OSV
steps; live OSV currently lists 6 vulns for lodash 4.17.11, the fixture
records the two this slice is verified against).
Injection (JS/TS): hand-written regex patterns — dynamic code execution,
shell commands built from input, SQL string building, unsanitized HTML;
no semgrep/opengrep shell-outs, AST/taint is a later upgrade path.
Working tree only — no git-history scanning. Local
path only — no cloning. OSV deps check is fixture-verified locally
(`--osv-fixture`); the live API path is separate code and OSV failure is
an `error`, never a `fail`.

## Guardrails and approval gates

- All checks are passive reads (headers, cert, DNS). No scans, no
  payloads, nothing that touches the target site.
- Work on `dev`, one PR per change, `dev` → `main`. Never merge into
  `main` directly: I want every PR reviewed and QA'd before it merges
  into `dev`, and `dev` → `main` releases happen only with my approval.
- `error` must never be reported as a vulnerability.

## Where decisions live

- I decide: `dev` → `main` releases, v2 scope calls (repo-scanning
  ecosystem, secrets-rule sources, web UI shape), and gate questions
  such as whether v1 is done.
- The reviewing agent handles: PR review/QA, merges into `dev`, and
  branch mechanics when a push fails.
- Anything not covered here: ask me before acting if it spends money,
  deletes or overwrites something, changes shared state, or speaks to
  anyone outside this project. Otherwise, act and report what was done.
