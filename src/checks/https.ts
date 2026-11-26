// https — redirect + HSTS (two results from one module).
import { CheckModule, CheckResult } from '../types.js';

async function fetchManual(url: string, signal: AbortSignal): Promise<Response> {
  return fetch(url, {
    method: 'HEAD',
    redirect: 'manual',
    signal,
    headers: { 'User-Agent': 'sec-check/1.0 (passive hygiene audit)' },
  });
}

export const httpsCheck: CheckModule = {
  id: 'https',
  async run(ctx) {
    const results: CheckResult[] = [];
    const signal = AbortSignal.timeout(20_000);

    // 1. http → https redirect (same port when a non-standard port is in use)
    try {
      const httpPort = ctx.port === 443 ? '' : `:${ctx.port}`;
      const httpUrl = `http://${ctx.hostname}${httpPort}/`;
      const res = await fetchManual(httpUrl, signal);
      const loc = res.headers.get('location') ?? '';
      if (res.status >= 300 && res.status < 400 && loc.startsWith('https://')) {
        results.push({
          id: 'https-redirect',
          name: 'HTTP → HTTPS redirect',
          status: 'pass',
          severity: 'high',
          detail: `http:// redirects to https:// (${res.status}).`,
        });
      } else if (res.status >= 200 && res.status < 300) {
        results.push({
          id: 'https-redirect',
          name: 'HTTP → HTTPS redirect',
          status: 'fail',
          severity: 'high',
          detail: 'Plain http:// serves content without redirecting to HTTPS.',
          fix: 'Redirect all http traffic to https with a 301 (e.g. Nginx: return 301 https://$host$request_uri;).',
        });
      } else {
        results.push({
          id: 'https-redirect',
          name: 'HTTP → HTTPS redirect',
          status: 'fail',
          severity: 'high',
          detail: `Unexpected http response: ${res.status}.`,
        });
      }
    } catch (err) {
      results.push({
        id: 'https-redirect',
        name: 'HTTP → HTTPS redirect',
        status: 'error',
        severity: 'high',
        detail: `Could not probe http:// (${(err as Error).message}).`,
      });
    }

    // 2. HSTS
    try {
      const res = await fetchManual(ctx.url.toString(), signal);
      const hsts = res.headers.get('strict-transport-security');
      if (!hsts) {
        results.push({
          id: 'hsts',
          name: 'HSTS header',
          status: 'fail',
          severity: 'high',
          detail: 'No Strict-Transport-Security header sent.',
          fix: 'Send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        });
      } else {
        const maxAge = /max-age=(\d+)/i.exec(hsts)?.[1];
        const strong = maxAge && Number(maxAge) >= 31_536_000 && /includesubdomains/i.test(hsts);
        results.push({
          id: 'hsts',
          name: 'HSTS header',
          status: strong ? 'pass' : 'fail',
          severity: 'high',
          detail: strong
            ? `HSTS set with max-age=${maxAge} and includeSubDomains.`
            : `HSTS present but weak: "${hsts}".`,
          ...(strong ? {} : { fix: 'Use: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' }),
        });
      }
    } catch (err) {
      results.push({
        id: 'hsts',
        name: 'HSTS header',
        status: 'error',
        severity: 'high',
        detail: `Could not read HTTPS headers (${(err as Error).message}).`,
      });
    }

    // 3. HSTS preload eligibility — judged from the header itself, not
    // the external preload list (offline by design; no API call at scan
    // time). Eligible iff max-age >= 31536000 AND includeSubDomains AND
    // the preload directive are all present. A site can pass `hsts`
    // (strong header) yet fail this (no preload directive) — that is
    // the point: preload is a separate, stricter bar.
    try {
      const res = await fetchManual(ctx.url.toString(), signal);
      const hsts = res.headers.get('strict-transport-security');
      if (!hsts) {
        results.push({
          id: 'hsts-preload',
          name: 'HSTS preload eligibility',
          status: 'fail',
          severity: 'low',
          detail: 'No Strict-Transport-Security header, so the site cannot be preload-eligible.',
          fix: 'Send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — then submit the domain at hstspreload.org.',
        });
      } else {
        const maxAge = /max-age=(\d+)/i.exec(hsts)?.[1];
        const eligible =
          maxAge !== undefined &&
          Number(maxAge) >= 31_536_000 &&
          /includesubdomains/i.test(hsts) &&
          /(?:^|;\s*)preload(?:\s|;|$)/i.test(hsts);
        results.push({
          id: 'hsts-preload',
          name: 'HSTS preload eligibility',
          status: eligible ? 'pass' : 'fail',
          severity: 'low',
          detail: eligible
            ? `Preload-eligible: max-age=${maxAge}, includeSubDomains, preload directive present.`
            : `Not preload-eligible: "${hsts}".`,
          ...(eligible
            ? {}
            : { fix: 'Send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — then submit the domain at hstspreload.org.' }),
        });
      }
    } catch (err) {
      results.push({
        id: 'hsts-preload',
        name: 'HSTS preload eligibility',
        status: 'error',
        severity: 'low',
        detail: `Could not read HTTPS headers (${(err as Error).message}).`,
      });
    }

    return results;
  },
};
