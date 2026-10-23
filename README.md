# 5-Minute Security Checker — v1 (URL checker)

Passive website hygiene audit. CLI first; reports are self-contained HTML
files — emailable, open offline.

## Run

```bash
npm run build        # compile TypeScript
node dist/cli.js <url>   # or: npm run check -- <url>
# example: npm run check -- https://example.com
```

Output: console summary + `reports/<host>-<timestamp>.html`.

## Checks (all passive — no scans, no payloads)

| id | name | weight |
|---|---|---|
| `https-redirect` | HTTP → HTTPS redirect | 10 |
| `hsts` | Strict-Transport-Security header | 12 |
| `csp` | Content-Security-Policy | 12 |
| `framing` | Clickjacking protection (X-Frame-Options / CSP frame-ancestors) | 8 |
| `nosniff` | X-Content-Type-Options: nosniff | 5 |
| `referrer-policy` | Referrer-Policy header | 3 |
| `version-leak` | Server/X-Powered-By version disclosure | 6 |
| `tls-cert` | Certificate validity + expiry | 12 |
| `tls-version` | TLS 1.2+ floor | 8 |
| `spf` | SPF TXT record | 7 |
| `dmarc` | DMARC TXT record (enforcing policy) | 7 |

Score = 100 − weights of failed checks. `error` means a check couldn't run
(timeout, DNS down) and never counts as a vulnerability. Every `fail` carries
a plain-English fix snippet in both the console output and the HTML report.

## Layout

- `src/checks/<id>.ts` — one file per check, filename = check id (see spec memory)
- `src/orchestrator.ts` — URL normalization, parallel runs, 20s timeouts
- `src/scorer.ts` — weights table (tune here, not in check logic)
- `src/report.ts` — self-contained HTML (inline CSS only)
- `src/cli.ts` — console summary + report file

## Acceptance (2026-10-17)

Test harness in `test-harness/`: two localhost servers — a hardened one and
a bare one (no headers, version-leaking Server banner). Results:

- Hardened server: **86/100 (Grade B)** — 8 passed, 2 failed (SPF/DMARC,
  honestly absent on localhost), 1 error (no plain-HTTP listener in harness).
- Bare server: **40/100 (Grade F)** — 8 failed, every finding with a fix.

Live-internet runs work on the user's own machine; the build VM's egress
policy blocks Node's `fetch`, so external targets can't be scanned from here.

## Next (v2)

Repo scanning (secrets, deps, injection) per the spec — ecosystem and
secrets-rule sources still open questions. JSON output flag still undecided.
