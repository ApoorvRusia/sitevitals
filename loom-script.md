# Loom script — SiteVitals v2 repo scanning (DRAFT skeleton)

> Status: skeleton — all four slices have landed and the demo commands
> below are verified. Record only after the final full regression passes.

## Format

60–90 seconds, screen recording, no facecam. One terminal, one browser
tab for the HTML report.

## Script

1. **Hook (0–10s)** — "Your website passes its security check. But the
   repo that builds it is leaking keys, running a vulnerable lodash, and
   calling eval on user input. SiteVitals now checks the repo too."
2. **Clean repo (10–30s)** — run `node dist/cli.js repo
   test-harness/fixtures/clean --json | jq '.score, .grade'`.
   Show: 100/100 (A), zero findings.
3. **Dirty repo (30–60s)** — run `node dist/cli.js repo
   test-harness/fixtures/dirty`. Show: red findings with file + line +
   redacted preview, a lodash finding with its GHSA id and fix version,
   an eval finding. Open the HTML report in `reports/` and scroll it.
4. **Close (60–75s)** — "Report only — it never changes your code, never
   prints a secret, never phones a secret home. `sitevitals repo <path>`."
   // TODO: final wording + on-screen captions once the UI text settles.

## B-roll / shots (TODO)

- [ ] Terminal: clean scan, dirty scan, `--json` output.
- [ ] Browser: dirty HTML report.
- [ ] Overlay: the three guarantees (report-only / redacted / no live
      secret verification).
