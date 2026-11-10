#!/bin/sh
# Generate the local-only self-signed cert/key the test harness needs.
# Run once from the repo root after a fresh clone:
#   sh test-harness/generate-cert.sh
# The cert/key are gitignored (*.pem) and must never be committed —
# generate a fresh pair per machine instead of reusing one from the repo.
# Uses the openssl command tested 2026-10-26 (see README "Local harness"):
# CN=localhost, SAN DNS:localhost + IP:127.0.0.1, 365 days.
set -eu
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "Wrote test-harness/key.pem and test-harness/cert.pem (local-only, gitignored)."
echo "Start the harness with: node test-harness/serve.mjs"
