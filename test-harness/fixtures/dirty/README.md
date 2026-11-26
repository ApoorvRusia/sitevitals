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
- **Injection (PR4)** — `src/app.js`: `eval`, `new Function`,
  `exec` with template interpolation, `exec` with string concat, SQL
  query with template interpolation, SQL query with string concat,
  `innerHTML` assignment, `document.write`, `dangerouslySetInnerHTML`.

Expected repo-scan result once all slices land: a low score with one
finding per plant above. Scanning this directory directly must flag
everything; scanning the repo root must flag nothing here, because the
root allowlist covers `test-harness/fixtures/dirty/**`.
