// Repo-scan types — the `sitevitals repo <path>` subcommand (v2).
// Findings reuse the v1 CheckResult shape so the scorer, report and
// --json machinery stay shared; repo-only fields are optional extras.
// Report-only: a finding never carries a secret value — `preview` is
// redacted at the engine, and the HTML/JSON renderers print only that.

import { CheckResult, Severity } from '../types.js';

export type { Severity };

export interface RepoFinding extends CheckResult {
  /** Path relative to the scanned root, when the finding is file-scoped. */
  file?: string;
  /** 1-based line number, when the finding is line-scoped. */
  line?: number;
  /** Secrets rule id / injection pattern id, when applicable. */
  ruleId?: string;
  /** REDACTED preview only — never a secret value. */
  preview?: string;
  /** Deps: package name / scanned version. */
  packageName?: string;
  packageVersion?: string;
  /** Deps: version that fixes every listed vuln for this package. */
  fixedVersion?: string;
  /** Deps: GHSA/CVE ids for this package. */
  vulnIds?: string[];
  /** Deps: ecosystem the package was queried in ('npm' | 'PyPI' | 'Go'). */
  ecosystem?: string;
}

export interface ScannedFile {
  relPath: string;
  absPath: string;
  content: string;
}

export interface AllowlistEntry {
  /** Exact rel path, or "dir/**" to cover a subtree. */
  path: string;
  reason: string;
  /** If set, only suppresses findings from this rule id. */
  rule?: string;
}

export interface Allowlist {
  entries: AllowlistEntry[];
  isAllowed(relPath: string, ruleId?: string): boolean;
}

export interface RepoCheckContext {
  root: string;
  allowlist: Allowlist;
  /** Path to a recorded OSV querybatch response (fixture verification). */
  osvFixture?: string;
}

export interface RepoCheckModule {
  id: string;
  name: string;
  /** One-line pass detail when the module finds nothing. */
  cleanDetail: (filesScanned: number) => string;
  run(files: ScannedFile[], ctx: RepoCheckContext): Promise<RepoFinding[]> | RepoFinding[];
}

export interface RepoScanOutput {
  target: string;
  scannedAt: string;
  filesScanned: number;
  filesSkipped: number;
  hitFileCap: boolean;
  results: RepoFinding[];
}
