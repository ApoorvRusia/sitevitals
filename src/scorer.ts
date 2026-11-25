// scorer — weights table → 0–100. Tune here, not in check logic.
// 'fail' subtracts its weight; 'error' subtracts nothing (unknown ≠ vulnerable).
import { CheckResult } from './types.js';

export const WEIGHTS: Record<string, number> = {
  'https-redirect': 10,
  hsts: 12,
  csp: 12,
  framing: 8,
  nosniff: 5,
  'referrer-policy': 3,
  'version-leak': 6,
  'cookie-flags': 6,
  'tls-cert': 12,
  'tls-version': 8,
  spf: 7,
  dmarc: 7,
};

export interface Score {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  passed: number;
  failed: number;
  errors: number;
}

export function scoreResults(results: CheckResult[], weights: Record<string, number> = WEIGHTS): Score {
  let score = 100;
  let passed = 0;
  let failed = 0;
  let errors = 0;
  for (const r of results) {
    if (r.status === 'pass') passed++;
    else if (r.status === 'fail') {
      failed++;
      score -= weights[r.id] ?? 5;
    } else errors++;
  }
  score = Math.max(0, Math.round(score));
  const grade: Score['grade'] = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  return { score, grade, passed, failed, errors };
}
