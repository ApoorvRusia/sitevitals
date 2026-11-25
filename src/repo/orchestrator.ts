// repo orchestrator — collects the working tree, then runs the registered
// repo check modules over it and assembles RepoScanOutput. Report-only:
// nothing here writes to the scanned repo, and no check ever leaves the
// machine except the OSV deps query (package names + versions only).
// Caps (max files / max file size) and the per-check timeouts are the
// emergency stop: a runaway scan is bounded, never unbounded.
import { RepoCheckModule, RepoFinding, RepoCheckContext, RepoScanOutput } from './types.js';
import { collectFiles, resolveRepoRoot } from './scanner.js';
import { loadAllowlist } from './allowlist.js';
import { secretsCheck } from './checks/secrets.js';
import { depsCheck } from './checks/deps.js';
import { injectionCheck } from './checks/injection.js';

// Check modules register here, one per slice:
// PR2 secrets, PR3 deps (npm first), PR4 injection (JS/TS).
const MODULES: RepoCheckModule[] = [secretsCheck, depsCheck, injectionCheck];

export interface RepoScanOptions {
  allowlistPath?: string;
  osvFixture?: string;
}

export async function runRepoScan(rawRoot: string, opts: RepoScanOptions = {}): Promise<RepoScanOutput> {
  const root = resolveRepoRoot(rawRoot);
  const { files, skippedFiles, hitFileCap } = collectFiles(root);
  const allowlist = loadAllowlist(root, opts.allowlistPath);
  const ctx: RepoCheckContext = { root, allowlist, osvFixture: opts.osvFixture };
  const results: RepoFinding[] = [];

  for (const mod of MODULES) {
    try {
      const findings = await mod.run(files, ctx);
      if (findings.length === 0) {
        results.push({
          id: `${mod.id}-clean`,
          name: mod.name,
          status: 'pass',
          severity: 'low',
          detail: mod.cleanDetail(files.length),
        });
      } else {
        results.push(...findings);
      }
    } catch (err) {
      // A crashed check is an error, never a vulnerability.
      results.push({
        id: mod.id,
        name: mod.name,
        status: 'error',
        severity: 'medium',
        detail: `${mod.name} could not run: ${(err as Error).message}`,
      });
    }
  }

  if (MODULES.length === 0) {
    results.push({
      id: 'repo-scaffold',
      name: 'Repo scan scaffold',
      status: 'pass',
      severity: 'low',
      detail: `Collected ${files.length} file(s) under caps; no check modules registered yet (they land one per slice: secrets, deps, injection).`,
    });
  }

  return {
    target: root,
    scannedAt: new Date().toISOString(),
    filesScanned: files.length,
    filesSkipped: skippedFiles,
    hitFileCap,
    results,
  };
}
