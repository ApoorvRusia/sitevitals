# Loom script — SiteVitals demo (FINAL, 2:30)

Voice: Kokoro am_adam (male English), ~150 wpm.
Rule: narration matches what's on screen, segment by segment.
Clarke records the screen in this exact order; Jarvis narrates the
"NARRATION" lines only, one audio file per segment, named 01–06.

## Segment 1 — Hook (0:00–0:15)
ON SCREEN: Landing page hero (apoorvrusia.github.io/sitevitals) —
rotating WebGL shield beside the headline. Slow scroll to the
"Built in-house. Zero dependencies." engine section.
NARRATION: "This is SiteVitals — a security auditor for websites and
repos that runs in one command, with zero runtime dependencies. The
checking engine is written from scratch, so there's no supply chain
to audit in the auditor."

## Segment 2 — URL mode, hardened site (0:15–0:45)
ON SCREEN: Terminal. Run:
  node dist/cli.js https://localhost:8443
(with NODE_EXTRA_CA_CERTS=test-harness/cert.pem). Checks stream in,
score lands at 81/100, Grade B. Open the generated HTML report,
scroll the three DNS failures with their fixes.
NARRATION: "Point it at any website and it runs eighteen passive
checks — HTTPS, headers, certificates, DNS records. This hardened
test site scores eighty-one out of a hundred. Every failure comes
with a plain-English fix, not just a red cross."

## Segment 3 — URL mode, bare site (0:45–1:10)
ON SCREEN: Terminal. Run:
  node dist/cli.js https://localhost:8080
Fourteen failures stream in with fix lines; score counts down to
15/100, Grade F.
NARRATION: "Now the same checks against a bare, unhardened site.
Fifteen out of a hundred. Fourteen failures — and every single one
tells you exactly what to add to fix it. A check that errors, like a
timeout, never counts against you."

## Segment 4 — Repo mode (1:10–1:40)
ON SCREEN: Terminal. Run:
  node dist/cli.js repo test-harness/fixtures/dirty
Show findings: a leaked secret (redacted preview, file + line), a
vulnerable lodash with its advisory ID and fixed version, an eval()
injection pattern. Then run the clean fixture: 100/100, Grade A.
NARRATION: "It also scans your repo — leaked secrets, vulnerable
dependencies, injection patterns. Secrets are always redacted;
SiteVitals never prints one, and never phones one home. A clean
repo scores a hundred."

## Segment 5 — Agent-first (1:40–2:05)
ON SCREEN: Terminal. Run:
  node dist/cli.js https://localhost:8443 --json
Pure JSON on stdout. Then:
  node dist/cli.js https://localhost:8080; echo $?
Exit code 1 prints. Then hardened with --min-score 70; echo $? → 0.
NARRATION: "SiteVitals is agent-first. JSON out, and an exit-code
contract — zero when the score passes your threshold, one when it
doesn't, two on error. Drop it in CI, or hand the repo URL to your
coding agent and let it run the audit itself."

## Segment 6 — Close (2:05–2:30)
ON SCREEN: GitHub repo page (github.com/ApoorvRusia/sitevitals),
README "Built in-house, zero dependencies" section, then back to
the landing page hero.
NARRATION: "Report-only — it never changes your code. One command,
eighteen checks, zero dependencies. SiteVitals is open source —
link below. Run it on your site today."

## Recording notes (Clarke)
- 1080p, terminal font large, dark theme to match landing page.
- Pause ~1s on each score landing before scrolling.
- No facecam. Captions burned in from the narration lines.
