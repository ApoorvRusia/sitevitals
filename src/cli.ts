// cli — two modes, one binary:
//   `node dist/cli.js <url> [--json]`        v1 URL audit (unchanged)
//   `node dist/cli.js repo <path> [--json] [--osv-fixture <file>] [--allowlist <file>]`
//                                            v2 repo scan (report-only)
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

const VERSION = '1.0.0';

function usage(): string {
  return 'Usage: node dist/cli.js <url> [--json] | node dist/cli.js repo <path> [--json] [--osv-fixture <file>] [--allowlist <file>]';
}

function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

async function runUrlCli(args: string[], jsonMode: boolean): Promise<void> {
  const target = args.find((a) => !a.startsWith('--'));
  if (!target) {
    console.error(usage());
    process.exit(1);
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
    return;
  }

  const icon = (r: (typeof scan.results)[number]) => (r.status === 'pass' ? '🟢' : r.status === 'fail' ? '🔴' : '⚪');
  for (const r of scan.results) {
    console.log(`${icon(r)} ${r.name.padEnd(28)} ${r.status.toUpperCase().padEnd(6)} ${r.detail}`);
    if (r.status === 'fail' && r.fix) console.log(`    Fix → ${r.fix}`);
  }
  console.log(`\nScore: ${score.score}/100 (Grade ${score.grade}) — ${score.passed} passed, ${score.failed} failed, ${score.errors} errors`);
  console.log(`Report: ${filePath}`);
}

async function runRepoCli(args: string[], jsonMode: boolean): Promise<void> {
  const target = args.find((a) => !a.startsWith('--'));
  if (!target) {
    console.error(usage());
    process.exit(1);
  }
  const osvFixture = flagValue(args, '--osv-fixture');
  const allowlistPath = flagValue(args, '--allowlist');
  if (osvFixture && !fs.existsSync(osvFixture)) {
    console.error(`OSV fixture file does not exist: ${osvFixture}`);
    process.exit(1);
  }
  if (allowlistPath && !fs.existsSync(allowlistPath)) {
    console.error(`Allowlist file does not exist: ${allowlistPath}`);
    process.exit(1);
  }

  if (!jsonMode) console.log(`Scanning repo ${target} … (report only — nothing is changed, no secrets are verified)\n`);
  let scan;
  try {
    scan = await runRepoScan(target, { osvFixture, allowlistPath });
  } catch (err) {
    console.error(`Repo scan failed: ${(err as Error).message}`);
    process.exit(1);
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
}

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  if (args.length === 0) {
    console.error(usage());
    process.exit(1);
  }
  if (args[0] === 'repo') {
    await runRepoCli(args.slice(1), jsonMode);
    return;
  }
  await runUrlCli(args, jsonMode);
}

main().catch((err) => {
  console.error('Scan failed:', (err as Error).message);
  process.exit(1);
});
