# Dirty fixture

A repo with planted findings — every secret, vulnerable dep and injection
pattern the scanner is supposed to catch. **All secrets are FAKE**
(documentation examples / random strings, never real credentials).

Planted, by check:

- **Secrets (PR2)** — `.env`: AWS access key id + secret, GitHub PAT,
  GitLab PAT, Slack bot token, Slack webhook URL, Stripe live key, npm
  token, SendGrid key, JWT. `id_rsa` (OpenSSH private key) and
  `rsa-key.pem` (RSA private key). `src/app.js`: generic `apiKey` and
  `dbPassword` assignments.
- **Secrets, extra rules (check 08)** — `.env`: Azure storage key,
  Google API key, Twilio API key, OpenAI API key, a postgres connection
  string with embedded credentials. `gcp-service-account.json`: a GCP
  service-account key file (type `service_account`, no private key
  block — so it flags exactly once, as `gcp-service-account`).
- **Deps (PR3)** — `package-lock.json`: lodash 4.17.11 (vulnerable;
  see `test-harness/fixtures/osv-lodash-vulnerable-response.json`).
- **Deps, Python (check 09)** — `requirements.txt`: idna 3.7
  (vulnerable: GHSA-65pc-fj4g-8rjx / CVE-2026-45409, fix 3.15) plus an
  unpinned `flask>=2.0` line that must be skipped, not flagged.
  `Pipfile.lock`: flask 2.0.1 (vulnerable: 4 OSV records, 2 CVEs, fix
  3.1.3). Verified with `osv-dirty-combined-response.json`.
- **Deps, Go (check 10)** — `go.mod`: gin v1.7.4 (vulnerable: 5 OSV
  records, 3 issues, fix v1.9.1). Verified with
  `osv-dirty-combined-response.json`.
- **Dockerfile (check 11)** — `Dockerfile`: `FROM node:latest`
  (unpinned), no `USER` instruction (runs as root), and
  `ENV STRIPE_KEY=sk_test_…` (a secret baked into a layer — flagged
  once here as `dockerfile-secret-env` and once by the secrets module
  as `stripe-secret`, because it is both a leaked secret and a layer
  problem).
- **License audit (check 12)** — `package-lock.json`:
  `fixture-gpl-lib` 1.0.0 (license GPL-3.0 → `license-copyleft`) and
  `fixture-nolicense-lib` 2.0.0 (no license field →
  `license-unknown`). lodash carries its real MIT license, so it is
  not flagged. The combined OSV fixture gains two empty results for
  the two fake packages (they are not real packages; OSV returns no
  vulns for them).
- **CI config (check 13)** — `.github/workflows/ci.yml`:
  `permissions: write-all` plus two unpinned actions
  (`actions/checkout@v4`, `actions/setup-node@v4`).
  `.github/workflows/release.yml`: top-level `permissions:` block
  granting `contents: write` + `packages: write`, one pinned action
  (`actions/checkout@<sha>`, must NOT be flagged) and one unpinned
  action.
- **Injection (PR4)** — `src/app.js`: `eval`, `new Function`,
  `exec` with template interpolation, `exec` with string concat, SQL
  query with template interpolation, SQL query with string concat,
  `innerHTML` assignment, `document.write`, `dangerouslySetInnerHTML`.

Expected repo-scan result once all slices land: a low score with one
finding per plant above. Scanning this directory directly must flag
everything; scanning the repo root must flag nothing here, because the
root allowlist covers `test-harness/fixtures/dirty/**`.
