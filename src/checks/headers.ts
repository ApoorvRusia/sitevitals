// headers — security response headers: CSP, framing, nosniff,
// Referrer-Policy, and version-leak detection.
import { CheckModule, CheckResult } from '../types.js';

const signal = () => AbortSignal.timeout(20_000);

export const headersCheck: CheckModule = {
  id: 'headers',
  async run(ctx) {
    let res: Response;
    try {
      res = await fetch(ctx.url.toString(), {
        method: 'HEAD',
        signal: signal(),
        headers: { 'User-Agent': 'sec-check/1.0 (passive hygiene audit)' },
      });
    } catch (err) {
      return [
        {
          id: 'headers-fetch',
          name: 'Security headers',
          status: 'error' as const,
          severity: 'medium' as const,
          detail: `Could not fetch headers (${(err as Error).message}).`,
        },
      ];
    }

    const get = (n: string) => res.headers.get(n);
    const results: CheckResult[] = [];

    // CSP
    const csp = get('content-security-policy');
    results.push({
      id: 'csp',
      name: 'Content-Security-Policy',
      status: csp ? 'pass' : 'fail',
      severity: 'high',
      detail: csp ? `CSP present (${csp.slice(0, 80)}${csp.length > 80 ? '…' : ''}).` : 'No Content-Security-Policy header.',
      fix: csp
        ? undefined
        : "Start with: Content-Security-Policy: default-src 'self'; and tighten per resource type.",
    });

    // Framing protection (X-Frame-Options or frame-ancestors)
    const xfo = get('x-frame-options');
    const frameAncestors = csp && /frame-ancestors/i.test(csp);
    if (xfo || frameAncestors) {
      results.push({
        id: 'framing',
        name: 'Clickjacking protection',
        status: 'pass',
        severity: 'medium',
        detail: xfo ? `X-Frame-Options: ${xfo}.` : 'CSP frame-ancestors directive present.',
      });
    } else {
      results.push({
        id: 'framing',
        name: 'Clickjacking protection',
        status: 'fail',
        severity: 'medium',
        detail: 'No X-Frame-Options header and no CSP frame-ancestors.',
        fix: "Send: X-Frame-Options: DENY (or SAMEORIGIN if frames are needed).",
      });
    }

    // nosniff
    const nosniff = get('x-content-type-options');
    results.push({
      id: 'nosniff',
      name: 'MIME sniffing protection',
      status: nosniff?.toLowerCase() === 'nosniff' ? 'pass' : 'fail',
      severity: 'medium',
      detail: nosniff ? `X-Content-Type-Options: ${nosniff}.` : 'No X-Content-Type-Options header.',
      fix: nosniff ? undefined : 'Send: X-Content-Type-Options: nosniff',
    });

    // Referrer-Policy
    const rp = get('referrer-policy');
    results.push({
      id: 'referrer-policy',
      name: 'Referrer-Policy',
      status: rp ? 'pass' : 'fail',
      severity: 'low',
      detail: rp ? `Referrer-Policy: ${rp}.` : 'No Referrer-Policy header.',
      fix: rp ? undefined : 'Send: Referrer-Policy: strict-origin-when-cross-origin',
    });

    // Version leak via Server / X-Powered-By
    const server = get('server');
    const powered = get('x-powered-by');
    const leak = [server, powered].filter((h): h is string => !!h && /\d/.test(h));
    if (leak.length > 0) {
      results.push({
        id: 'version-leak',
        name: 'Version disclosure',
        status: 'fail',
        severity: 'low',
        detail: `Headers disclose versions: ${leak.join(', ')}.`,
        fix: 'Hide version banners (e.g. Nginx: server_tokens off; strip X-Powered-By at the framework level).',
      });
    } else {
      results.push({
        id: 'version-leak',
        name: 'Version disclosure',
        status: 'pass',
        severity: 'low',
        detail: server || powered ? `Server header present but generic (${server ?? powered}).` : 'No revealing Server/X-Powered-By headers.',
      });
    }

    return results;
  },
};
