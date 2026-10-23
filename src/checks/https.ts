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

    return results;
  },
};
