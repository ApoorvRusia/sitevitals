// headers — security response headers: CSP, framing, nosniff,
// Referrer-Policy, version-leak detection, cookie flags,
// Permissions-Policy, and cross-origin isolation headers.
import { CheckModule, CheckResult } from '../types.js';

const signal = () => AbortSignal.timeout(20_000);

/** A cookie's attributes, lower-cased, from one Set-Cookie string. */
function cookieAttrs(setCookie: string): Set<string> {
  return new Set(
    setCookie
      .split(';')
      .slice(1)
      .map((a) => a.trim().split('=')[0].toLowerCase())
      .filter(Boolean),
  );
}

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

    // Permissions-Policy
    const pp = get('permissions-policy');
    results.push({
      id: 'permissions-policy',
      name: 'Permissions-Policy',
      status: pp ? 'pass' : 'fail',
      severity: 'low',
      detail: pp ? `Permissions-Policy present (${pp.slice(0, 80)}${pp.length > 80 ? '…' : ''}).` : 'No Permissions-Policy header.',
      fix: pp ? undefined : "Send: Permissions-Policy: camera=(), microphone=(), geolocation=() (add any feature the site actually uses).",
    });

    // Isolation headers — fail only on a missing COOP; COEP/CORP are
    // reported as info in the detail, not scored. COOP is the one that
    // protects the top-level document against cross-origin leaks; COEP
    // and CORP matter per-resource and are a later, stricter bar.
    const coop = get('cross-origin-opener-policy');
    const coep = get('cross-origin-embedder-policy');
    const corp = get('cross-origin-resource-policy');
    const isolationInfo = [
      coep ? 'COEP present' : 'COEP absent',
      corp ? `CORP: ${corp}` : 'CORP absent',
    ].join('; ');
    if (coop) {
      results.push({
        id: 'isolation-headers',
        name: 'Cross-origin isolation',
        status: 'pass',
        severity: 'medium',
        detail: `COOP: ${coop}. ${isolationInfo}.`,
      });
    } else {
      results.push({
        id: 'isolation-headers',
        name: 'Cross-origin isolation',
        status: 'fail',
        severity: 'medium',
        detail: `No Cross-Origin-Opener-Policy header. ${isolationInfo}.`,
        fix: 'Send: Cross-Origin-Opener-Policy: same-origin (add Cross-Origin-Embedder-Policy: require-corp once all subresources carry CORP or CORS).',
      });
    }

    // security.txt — /.well-known/security.txt, pass on any 2xx.
    // A GET with the body cancelled immediately: the file is tiny by
    // spec, and we only need its status, not its contents.
    try {
      const secUrl = new URL('/.well-known/security.txt', ctx.url);
      const secRes = await fetch(secUrl.toString(), {
        method: 'GET',
        signal: signal(),
        headers: { 'User-Agent': 'sec-check/1.0 (passive hygiene audit)' },
      });
      await secRes.body?.cancel().catch(() => undefined);
      if (secRes.status >= 200 && secRes.status < 300) {
        results.push({
          id: 'security-txt',
          name: 'security.txt',
          status: 'pass',
          severity: 'low',
          detail: `security.txt served at /.well-known/security.txt (${secRes.status}).`,
        });
      } else {
        results.push({
          id: 'security-txt',
          name: 'security.txt',
          status: 'fail',
          severity: 'low',
          detail: `No security.txt (/.well-known/security.txt returned ${secRes.status}).`,
          fix: 'Publish /.well-known/security.txt with at least a Contact line (RFC 9116): Contact: mailto:security@example.com',
        });
      }
    } catch (err) {
      results.push({
        id: 'security-txt',
        name: 'security.txt',
        status: 'error',
        severity: 'low',
        detail: `Could not fetch security.txt (${(err as Error).message}).`,
      });
    }

    // Cookie flags — Secure, HttpOnly, SameSite on every Set-Cookie.
    // A GET, not the HEAD above: some servers only set cookies on GET.
    // The body is cancelled immediately after the headers arrive — we
    // never download page content. No cookies at all is a pass: a site
    // with no cookies has no cookie risk to secure.
    try {
      const cookieRes = await fetch(ctx.url.toString(), {
        method: 'GET',
        signal: signal(),
        headers: { 'User-Agent': 'sec-check/1.0 (passive hygiene audit)' },
      });
      const cookies = cookieRes.headers.getSetCookie();
      await cookieRes.body?.cancel().catch(() => undefined);
      if (cookies.length === 0) {
        results.push({
          id: 'cookie-flags',
          name: 'Cookie flags',
          status: 'pass',
          severity: 'medium',
          detail: 'No cookies set — nothing to secure.',
        });
      } else {
        const bad = cookies.filter((c) => {
          const attrs = cookieAttrs(c);
          return !attrs.has('secure') || !attrs.has('httponly') || !attrs.has('samesite');
        });
        if (bad.length === 0) {
          results.push({
            id: 'cookie-flags',
            name: 'Cookie flags',
            status: 'pass',
            severity: 'medium',
            detail: `All ${cookies.length} cookie(s) carry Secure, HttpOnly and SameSite.`,
          });
        } else {
          const name = bad[0].split(';')[0].trim();
          results.push({
            id: 'cookie-flags',
            name: 'Cookie flags',
            status: 'fail',
            severity: 'medium',
            detail: `${bad.length} of ${cookies.length} cookie(s) missing Secure, HttpOnly or SameSite (e.g. ${name}).`,
            fix: 'Set cookies with all three flags: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax (Strict for session cookies that never need cross-site sends).',
          });
        }
      }
    } catch (err) {
      results.push({
        id: 'cookie-flags',
        name: 'Cookie flags',
        status: 'error',
        severity: 'medium',
        detail: `Could not read cookies (${(err as Error).message}).`,
      });
    }

    return results;
  },
};
