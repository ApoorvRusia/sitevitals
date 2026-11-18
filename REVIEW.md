# REVIEW.md — SiteVitals v1 review (for Clarke's QA; merge awaits Apoorv's approval)

_Updated 2026-11-10 from the 2026-10-27 draft: reflects PRs merged into `dev`
since then (v2 `--json` flag, merge-wording fix, harness cert-generate step).
Verification claims below are unchanged — they describe the v1 code as verified
2026-10-26. See REVIEW-UPDATE-NOTES.md alongside this file for what changed
and what Clarke should confirm on the diff._

## What this PR is

- Branch state: this PR adds only this file, on a branch off `dev`, PR into
  `dev` (per the current branch model: branches off `dev`, PRs into `dev`
  only). `dev` now carries the verified v1 code plus v2 PR #1 (`--json` flag,
  merged 2026-11-05), PR #2 (merge-wording fix) and PR #3 (harness
  cert-generate step), both merged 2026-11-10. `main` is untouched and
  remains the production branch. No merge to `main` has happened; that
  release waits on Apoorv's approval after Clarke's review, and on the
  still-pending v1 gate decision.
- Verification: harness-verified 2026-10-26 midday PDT. Hardened
  https://localhost:8443 = 86/100 (Grade B): 8 passed, 2 failed (SPF, DMARC —
  honestly absent on localhost), 1 error (https-redirect: no plain-HTTP
  listener in the harness). Bare https://localhost:8080 = 40/100 (Grade F):
  2 passed, 8 failed, 1 error, every finding with a plain-English fix.
  Matches the README acceptance exactly.
- Verification basis: the run was against code blob-identical to current
  master HEAD (56ffb18). Commits after the run touched the README and added
  example reports (`examples/`) only; every source file, the harness server,
  package.json and tsconfig were compared file-for-file and match. Method:
  `npm ci`, `npm run build`, fresh self-signed cert (CN=localhost,
  SAN DNS:localhost/IP:127.0.0.1, 365 days), CLI run with
  NODE_EXTRA_CA_CERTS pointing at that cert. The v2 `--json` flag merged
  since is additive only (`--json` output; default output unchanged), so it
  does not affect this verification.
- Live-site runs: this VM's egress blocks Node fetch to external targets, so
  live-site verification must run on Apoorv's machine; the harness result
  above is the localhost result.

## What works as documented

- CLI: `npm run build`, then `node dist/cli.js <url>` /
  `npm run check -- <url>`; console summary + self-contained HTML report
  in `reports/`.
- All 11 checks run (HTTPS redirect; HSTS, CSP, framing, nosniff,
  referrer-policy, version-leak; TLS cert + TLS version floor; SPF, DMARC),
  scoring 100 minus failed weights; `error` never counts as a vulnerability.
- Every failure carries a plain-English fix in console + HTML.
- Example reports now ship in `examples/` (hardened + bare localhost reports).

## Doc / code mismatches

1. README Layout says `src/checks/<id>.ts` — one file per check id. Actual
   layout is 4 grouped files: `dns.ts`, `headers.ts`, `https.ts`, `tls.ts`.
   Still open — recommend fixing the Layout section to describe the
   grouped files.
2. ~~README Run section omits the certificate-trust step for the local
   harness.~~ Partly resolved in `dev` by PR #3 (harness cert-generate step,
   merged 2026-11-10): a fresh checkout can now generate the cert
   (`test-harness/generate-cert.sh`), and the trust step
   (`NODE_EXTRA_CA_CERTS=test-harness/cert.pem`) is documented in the
   README's Example outputs section. But the Run section itself still
   doesn't state it — verified against the `dev` README 2026-11-10.
   Recommend one line in Run (generate the cert, then run with
   NODE_EXTRA_CA_CERTS set). Without it, Node's fetch rejects the
   self-signed cert and the header/TLS checks error instead of passing,
   so the hardened total can still read 86 while hiding that failure mode.
3. The harness has no plain-HTTP listener, so the https-redirect check
   always reports `error` on localhost runs. That is a harness limitation,
   not a product bug — but it means the redirect check is unverified by
   the harness and needs a live-site run to confirm. Still open.
4. ~~`*.pem` (harness cert/key) are gitignored, so a fresh checkout cannot
   run the harness until a cert is generated.~~ Resolved by PR #3's
   cert-generate step (merged 2026-11-10) — `test-harness/generate-cert.sh`
   is on `dev`, verified.

## Bugs / risks

- None found that break the documented behaviour. Notes, not blockers:
  - `error` results never penalize the score by design. A check that can't
    run (timeout, DNS down, cert rejected) therefore looks neutral rather
    than bad. For a hygiene tool this is the documented choice, but a run
    full of errors can still show a high score — read the report with the
    error count, not just the number.
  - SPF/DMARC fail on localhost by design (no DNS records for localhost).
    On live sites they reflect real DNS.
  - Scores cover only the target's public surface; this is a passive
    hygiene check, not a full audit or pentest (the README already says
    this).

## Prioritized v2 next steps

1. ~~JSON output flag — smallest change, makes the checker composable (CI,
   scripts, other tools). Recommended first.~~ Done — merged into `dev` as
   PR #1, 2026-11-05 (`--json` flag, default output unchanged).
2. Repo scanning (secrets, vulnerable dependencies, injection patterns) —
   the bigger build; ecosystem and secrets-rule sources are still open
   questions and need decisions before implementation. Next in queue.
3. Web UI — largest surface; last.
- Also recommended alongside any v1 landing: fix the README Layout section
  (grouped check files, item 1 above).

## Branch state + merge gate

- `main`: production branch, untouched by this PR.
- `dev`: verified v1 code + v2 `--json` flag + PR #2 + PR #3.
- This PR: this file only, branch off `dev` into `dev`, open for Clarke's
  review. Nothing is merged to `main`. Merging `dev` into `main` waits on
  Apoorv's approval and the pending v1 gate decision.
