// cli — two modes, one binary:
//   `node dist/cli.js <url> [--json]`        v1 URL audit (unchanged)
//   `node dist/cli.js repo <path> [--json] [--osv-fixture <file>] [--allowlist <file>]`
//                                            v2 repo scan (report-only)
//   `node dist/cli.js repo <path> --sbom [--sbom-out <file>]`
//                                            CycloneDX-ish inventory, no scoring
// --json prints pure JSON on stdout in both modes (for piping into other
// tools); the HTML report is still written and its path is in the payload.
import fs from 'node:fs';
import path from 'node:path';
import { runAllChecks } from './orchestrator.js';
import { scoreResults } from './scorer.js';
import { renderReport } from './report.js';
import { runRepoScan } from './repo/orchestrator.js';
import { scoreRepoResults } from './repo/scorer.js';
import { renderRepoReport } from './repo/report.js';
import { buildSbom } from './repo/sbom.js';
import { collectFiles, resolveRepoRoot } from './repo/scanner.js';

const VERSION = '1.0.0';

function usage(): string {
  return 'Usage: node dist/cli.js <url> [--json] [--min-score <n>] | node dist/cli.js repo <path> [--json] [--min-score <n>] [--osv-fixture <file>] [--allowlist <file>] [--sbom [--sbom-out <file>]]';
}

// Exit-code contract (agents + CI rely on this):
//   0 — scan completed and score >= --min-score (default 70)
//   1 — scan completed and score <  --min-score
//   2 — usage or runtime error (no score produced)
// --sbom mode exits 0 on success (it inventories; it does not score).
function minScoreFrom(args: string[]): number {
  const raw = flagValue(args, '--min-score');
  const n = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(n) && n >= 0 && n <= 100 ? n : 70;
}

function applyScoreExitCode(score: number, minScore: number): void {
  process.exitCode = score >= minScore ? 0 : 1;
}

function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

async function runUrlCli(args: string[], jsonMode: boolean): Promise<void> {
  const target = args.find((a) => !a.startsWith('--'));
  if (!target) {
    console.error(usage());
    process.exit(2);
  }

  if (!jsonMode) console.log(`Scanning ${target} … (passive checks only)\n`);
  const scan = await runAllChecks(target);
  const score = scoreResults(scan.results);

  const reportsDir = path.resolve(process.cwd(), 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });
  const fileName = `${scan.hostname}-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.html`;
  const filePath = path.join(reportsDir, fileName);
  fs.writeFileSync(filePath, renderReport(scan, score));

  if (jsonMode) {
    // Pure JSON on stdout so `| jq` and other tools can consume it directly.
    // The HTML report is still written; its path is in the payload.
    console.log(
      JSON.stringify(
        {
          tool: 'sitevitals',
          version: VERSION,
          target: scan.target,
          hostname: scan.hostname,
          scannedAt: scan.scannedAt,
          score: score.score,
          grade: score.grade,
          passed: score.passed,
          failed: score.failed,
          errors: score.errors,
          results: scan.results,
          report: filePath,
        },
        null,
        2,
      ),
    );
    applyScoreExitCode(score.score, minScoreFrom(args));
    return;
  }

  const icon = (r: (typeof scan.results)[number]) => (r.status === 'pass' ? '🟢' : r.status === 'fail' ? '🔴' : '⚪');
  for (const r of scan.results) {
    console.log(`${icon(r)} ${r.name.padEnd(28)} ${r.status.toUpperCase().padEnd(6)} ${r.detail}`);
    if (r.status === 'fail' && r.fix) console.log(`    Fix → ${r.fix}`);
  }
  console.log(`\nScore: ${score.score}/100 (Grade ${score.grade}) — ${score.passed} passed, ${score.failed} failed, ${score.errors} errors`);
  console.log(`Report: ${filePath}`);
  applyScoreExitCode(score.score, minScoreFrom(args));
}

async function runRepoCli(args: string[], jsonMode: boolean): Promise<void> {
  const target = args.find((a) => !a.startsWith('--'));
  if (!target) {
    console.error(usage());
    process.exit(2);
  }
  const osvFixture = flagValue(args, '--osv-fixture');
  const allowlistPath = flagValue(args, '--allowlist');
  const sbomMode = args.includes('--sbom');
  const sbomOut = flagValue(args, '--sbom-out');
  if (osvFixture && !fs.existsSync(osvFixture)) {
    console.error(`OSV fixture file does not exist: ${osvFixture}`);
    process.exit(2);
  }
  if (allowlistPath && !fs.existsSync(allowlistPath)) {
    console.error(`Allowlist file does not exist: ${allowlistPath}`);
    process.exit(2);
  }

  // --sbom mode inventories the repo instead of scoring it: no checks
  // run, no score is computed, nothing is written to reports/.
  if (sbomMode) {
    let root: string;
    let files: { relPath: string; absPath: string; content: string }[];
    try {
      root = resolveRepoRoot(target);
      files = collectFiles(root).files;
    } catch (err) {
      console.error(`SBOM failed: ${(err as Error).message}`);
      process.exit(2);
    }
    const sbom = buildSbom(root, files, VERSION);
    const text = JSON.stringify(sbom, null, 2);
    if (sbomOut) {
      fs.writeFileSync(path.resolve(sbomOut), text + '\n');
      console.log(`SBOM written to ${path.resolve(sbomOut)} (${sbom.components.length} components)`);
    } else {
      console.log(text);
    }
    return;
  }

  if (!jsonMode) console.log(`Scanning repo ${target} … (report only — nothing is changed, no secrets are verified)\n`);
  let scan;
  try {
    scan = await runRepoScan(target, { osvFixture, allowlistPath });
  } catch (err) {
    console.error(`Repo scan failed: ${(err as Error).message}`);
    process.exit(2);
  }
  const score = scoreRepoResults(scan.results);

  const reportsDir = path.resolve(process.cwd(), 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });
  const base = path.basename(scan.target) || 'repo';
  const fileName = `repo-${base}-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.html`;
  const filePath = path.join(reportsDir, fileName);
  fs.writeFileSync(filePath, renderRepoReport(scan, score));

  if (jsonMode) {
    console.log(
      JSON.stringify(
        {
          tool: 'sitevitals',
          version: VERSION,
          mode: 'repo',
          target: scan.target,
          scannedAt: scan.scannedAt,
          filesScanned: scan.filesScanned,
          filesSkipped: scan.filesSkipped,
          hitFileCap: scan.hitFileCap,
          score: score.score,
          grade: score.grade,
          passed: score.passed,
          failed: score.failed,
          errors: score.errors,
          results: scan.results,
          report: filePath,
        },
        null,
        2,
      ),
    );
    applyScoreExitCode(score.score, minScoreFrom(args));
    return;
  }

  const icon = (r: (typeof scan.results)[number]) => (r.status === 'pass' ? '🟢' : r.status === 'fail' ? '🔴' : '⚪');
  for (const r of scan.results) {
    const where = r.file ? ` ${r.file}${r.line !== undefined ? `:${r.line}` : ''}` : '';
    console.log(`${icon(r)} ${r.name.padEnd(28)} ${r.status.toUpperCase().padEnd(6)} ${r.detail}${where}`);
    if (r.status === 'fail' && r.fix) console.log(`    Fix → ${r.fix}`);
  }
  console.log(`\nScore: ${score.score}/100 (Grade ${score.grade}) — ${score.passed} passed, ${score.failed} failed, ${score.errors} errors — ${scan.filesScanned} files scanned${scan.filesSkipped ? `, ${scan.filesSkipped} skipped` : ''}${scan.hitFileCap ? ' — FILE CAP HIT' : ''}`);
  console.log(`Report: ${filePath}`);
  applyScoreExitCode(score.score, minScoreFrom(args));
}

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  if (args.length === 0) {
    console.error(usage());
    process.exit(2);
  }
  if (args[0] === 'repo') {
    await runRepoCli(args.slice(1), jsonMode);
    return;
  }
  await runUrlCli(args, jsonMode);
}

main().catch((err) => {
  console.error('Scan failed:', (err as Error).message);
  process.exit(2);
});
