// cli — `node dist/cli.js <url> [--json]`: console summary + self-contained
// HTML report, or machine-readable JSON on stdout with --json (for piping
// into other tools; stdout is pure JSON in that mode).
import fs from 'node:fs';
import path from 'node:path';
import { runAllChecks } from './orchestrator.js';
import { scoreResults } from './scorer.js';
import { renderReport } from './report.js';

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const target = args.find((a) => !a.startsWith('--'));
  if (!target) {
    console.error('Usage: node dist/cli.js <url> [--json]');
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
          version: '1.0.0',
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

main().catch((err) => {
  console.error('Scan failed:', (err as Error).message);
  process.exit(1);
});
