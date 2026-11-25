// repo scorer — weights table for repo findings, 0–100, same grade bands
// as v1. Reuses the v1 scoreResults via its optional weights parameter;
// 'error' never counts as a vulnerability, exactly like the URL scorer.
import { CheckResult } from '../types.js';
import { Score, scoreResults } from '../scorer.js';

export const REPO_WEIGHTS: Record<string, number> = {
  // PR2 secrets (finding id = rule id):
  'aws-access-key': 15,
  'aws-secret-key': 15,
  'github-pat': 15,
  'gitlab-pat': 15,
  'slack-token': 12,
  'slack-webhook': 12,
  'stripe-secret': 15,
  'private-key': 15,
  jwt: 10,
  'npm-token': 12,
  'sendgrid-key': 12,
  'generic-api-key': 10,
  'generic-password': 8,
  // PR3 deps, PR4 injection: weights land with their slice.
  // Unknown ids fall back to 5 in scoreResults, so a new check is never
  // silently unscored.
};

export function scoreRepoResults(results: CheckResult[]): Score {
  return scoreResults(results, REPO_WEIGHTS);
}
