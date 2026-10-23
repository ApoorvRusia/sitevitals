// dns — SPF and DMARC via TXT records (read-only DNS lookups).
import dns from 'node:dns/promises';
import { CheckModule, CheckResult } from '../types.js';

async function txtRecords(name: string): Promise<string[]> {
  try {
    const recs = await dns.resolveTxt(name);
    return recs.map((r) => r.join(''));
  } catch {
    return [];
  }
}

export const dnsCheck: CheckModule = {
  id: 'dns',
  async run(ctx) {
    const results: CheckResult[] = [];

    // SPF
    const rootTxt = await txtRecords(ctx.hostname);
    const spf = rootTxt.find((t) => t.toLowerCase().startsWith('v=spf1'));
    if (spf) {
      results.push({
        id: 'spf',
        name: 'SPF record',
        status: 'pass',
        severity: 'medium',
        detail: `SPF published: ${spf.length > 90 ? spf.slice(0, 90) + '…' : spf}.`,
      });
    } else {
      results.push({
        id: 'spf',
        name: 'SPF record',
        status: 'fail',
        severity: 'medium',
        detail: 'No SPF TXT record on the domain — anyone can spoof email from it.',
        fix: 'Publish TXT: v=spf1 include:<your-mail-provider> -all (replace with your actual sender set).',
      });
    }

    // DMARC
    const dmarcTxt = await txtRecords(`_dmarc.${ctx.hostname}`);
    const dmarc = dmarcTxt.find((t) => t.toLowerCase().startsWith('v=dmarc1'));
    if (dmarc) {
      const policy = /p=([a-z]+)/i.exec(dmarc)?.[1]?.toLowerCase();
      const strict = policy === 'quarantine' || policy === 'reject';
      results.push({
        id: 'dmarc',
        name: 'DMARC record',
        status: strict ? 'pass' : 'fail',
        severity: 'medium',
        detail: dmarc ? `DMARC published (p=${policy ?? 'unknown'}).` : 'DMARC TXT not found.',
        fix: strict ? undefined : 'Publish _dmarc TXT with an enforcing policy: v=DMARC1; p=quarantine; rua=mailto:dmarc@' + ctx.hostname,
      });
    } else {
      results.push({
        id: 'dmarc',
        name: 'DMARC record',
        status: 'fail',
        severity: 'medium',
        detail: 'No DMARC TXT record at _dmarc.' + ctx.hostname,
        fix: 'Publish TXT at _dmarc: v=DMARC1; p=quarantine; rua=mailto:dmarc@' + ctx.hostname,
      });
    }

    return results;
  },
};
