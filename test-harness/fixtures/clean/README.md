# Clean fixture

A repo with nothing to flag: no secrets, no vulnerable dependencies,
no injection patterns. Expected repo-scan result: **100/100 (A)**.

It also carries the clean-side Python manifests: `requirements.txt`
(click 8.1.7, pinned and clean, plus an unpinned `requests>=2.0` line
that must be skipped) and `Pipfile.lock` (click 8.1.7 — same package as
requirements.txt, so the dep check must dedupe it to one query).
And the clean-side Go manifest: `go.mod` requiring uuid v1.6.0
(clean, in a `require` block).
And the clean-side Dockerfile: `FROM node:20.11.0` (pinned),
`USER node` (non-root), `ENV NODE_ENV=production` (no secret).
The clean lockfile's lodash entry carries its real MIT license, so
the license audit passes it.
Verified with `osv-clean-combined-response.json`.
