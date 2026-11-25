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
  // PR3 deps (finding id is the module-level 'deps-vulnerable'; one finding
  // per vulnerable package, however many vulns it has):
  'deps-vulnerable': 12,
  // PR4 injection (finding id = pattern id):
  'eval-call': 12,
  'function-constructor': 12,
  'exec-template': 12,
  'exec-concat': 12,
  'sql-string-concat': 10,
  'inner-html': 8,
  'document-write': 6,
  'dangerously-set-inner-html': 8,
  // Unknown ids fall back to 5 in scoreResults, so a new check is never
  // silently unscored.
  // Unknown ids fall back to 5 in scoreResults, so a new check is never
  // silently unscored.
};

export function scoreRepoResults(results: CheckResult[]): Score {
  return scoreResults(results, REPO_WEIGHTS);
}
