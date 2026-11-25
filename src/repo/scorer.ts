// repo scorer — weights table for repo findings, 0–100, same grade bands
// as v1. Reuses the v1 scoreResults via its optional weights parameter;
// 'error' never counts as a vulnerability, exactly like the URL scorer.
import { CheckResult } from '../types.js';
import { Score, scoreResults } from '../scorer.js';

export const REPO_WEIGHTS: Record<string, number> = {
  // PR1: no finding-producing checks yet — weights land with their slice:
  // PR2 secrets, PR3 deps, PR4 injection. Unknown ids fall back to 5
  // in scoreResults, so a new check is never silently unscored.
};

export function scoreRepoResults(results: CheckResult[]): Score {
  return scoreResults(results, REPO_WEIGHTS);
}
