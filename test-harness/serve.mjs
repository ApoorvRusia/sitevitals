// Test harness: two localhost sites — a "good" hardened server and a
// "bad" bare one. Run: node test-harness/serve.mjs, then in another shell
// run the CLI against https://localhost:8443 (good) and https://localhost:8080 (bad).
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';

const key = fs.readFileSync(new URL('./key.pem', import.meta.url));
const cert = fs.readFileSync(new URL('./cert.pem', import.meta.url));

const GOOD_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
};

const good = https.createServer({ key, cert }, (req, res) => {
  res.writeHead(200, GOOD_HEADERS);
  res.end('good');
});

const bad = https.createServer({ key, cert }, (req, res) => {
  // Bare: no security headers at all, plus a version-leaking Server header.
  res.writeHead(200, { server: 'BadServer/1.2.3', 'x-powered-by': 'Express/4.21' });
  res.end('bad');
});

good.listen(8443, () => console.log('good → https://localhost:8443'));
bad.listen(8080, () => console.log('bad  → https://localhost:8080'));
