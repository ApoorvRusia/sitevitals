// cli — `npx sec-check <url>`: console summary + self-contained HTML report.
import fs from 'node:fs';
import path from 'node:path';
import { runAllChecks } from './orchestrator.js';
import { scoreResults } from './scorer.js';
import { renderReport } from './report.js';

async function main() {
  const target = process.argv[2];
  if (!target) {
    console.error('Usage: npx sec-check <url>');
    process.exit(1);
  }

  console.log(`Scanning ${target} … (passive checks only)\n`);
  const scan = await runAllChecks(target);
  const score = scoreResults(scan.results);

  const icon = (r: (typeof scan.results)[number]) => (r.status === 'pass' ? '🟢' : r.status === 'fail' ? '🔴' : '⚪');
  for (const r of scan.results) {
    console.log(`${icon(r)} ${r.name.padEnd(28)} ${r.status.toUpperCase().padEnd(6)} ${r.detail}`);
    if (r.status === 'fail' && r.fix) console.log(`    Fix → ${r.fix}`);
  }
  console.log(`\nScore: ${score.score}/100 (Grade ${score.grade}) — ${score.passed} passed, ${score.failed} failed, ${score.errors} errors`);

  const reportsDir = path.resolve(process.cwd(), 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });
  const fileName = `${scan.hostname}-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.html`;
  const filePath = path.join(reportsDir, fileName);
  fs.writeFileSync(filePath, renderReport(scan, score));
  console.log(`Report: ${filePath}`);
}

main().catch((err) => {
  console.error('Scan failed:', (err as Error).message);
  process.exit(1);
});
