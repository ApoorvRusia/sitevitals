// orchestrator — normalizes the target URL, runs all checks in parallel
// with a 20s per-check timeout, and collects results.
import { CheckContext, CheckModule, CheckResult } from './types.js';
import { httpsCheck } from './checks/https.js';
import { headersCheck } from './checks/headers.js';
import { tlsCheck } from './checks/tls.js';
import { dnsCheck } from './checks/dns.js';

const CHECKS: CheckModule[] = [httpsCheck, headersCheck, tlsCheck, dnsCheck];

export interface ScanOutput {
  target: string;
  hostname: string;
  scannedAt: string;
  results: CheckResult[];
}

export function normalizeTarget(raw: string): CheckContext {
  let input = raw.trim();
  if (!/^https?:\/\//i.test(input)) input = `https://${input}`;
  const url = new URL(input);
  // Force https: this is a hygiene tool for live sites, not an http surveyor.
  url.protocol = 'https:';
  url.hash = '';
  const hostname = url.hostname.replace(/:\d+$/, '');
  url.hostname = hostname;
  const port = url.port ? Number(url.port) : 443;
  return { url, hostname, port };
}

async function runWithTimeout(check: CheckModule, ctx: CheckContext): Promise<CheckResult[]> {
  return Promise.race([
    check.run(ctx),
    new Promise<CheckResult[]>((resolve) =>
      setTimeout(
        () =>
          resolve([
            {
              id: `${check.id}-timeout`,
              name: check.id,
              status: 'error',
              severity: 'medium',
              detail: `${check.id} exceeded the 20s timeout.`,
            },
          ]),
        20_000,
      ),
    ),
  ]);
}

export async function runAllChecks(rawTarget: string): Promise<ScanOutput> {
  const ctx = normalizeTarget(rawTarget);
  const settled = await Promise.allSettled(CHECKS.map((c) => runWithTimeout(c, ctx)));
  const results: CheckResult[] = [];
  for (const s of settled) {
    if (s.status === 'fulfilled') results.push(...s.value);
    else
      results.push({
        id: 'orchestrator',
        name: 'Check runner',
        status: 'error',
        severity: 'medium',
        detail: `A check crashed: ${(s.reason as Error)?.message ?? s.reason}.`,
      });
  }
  return {
    target: ctx.url.toString(),
    hostname: ctx.hostname,
    scannedAt: new Date().toISOString(),
    results,
  };
}
