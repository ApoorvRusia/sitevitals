// repo report — self-contained HTML for `sitevitals repo`, same visual
// language as the URL report (inline CSS only, opens offline, emailable).
// Findings show rule id + file + line + REDACTED preview only; a secret
// value can never appear here because the preview is redacted at the
// engine, before any renderer sees it.
import { Score } from '../scorer.js';
import { RepoFinding, RepoScanOutput } from './types.js';

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

const statusBadge = (r: RepoFinding) =>
  r.status === 'pass' ? '🟢 PASS' : r.status === 'fail' ? '🔴 FAIL' : '⚪ ERROR';

const sevTag = (r: RepoFinding) => (r.status === 'fail' ? ` <span class="sev ${r.severity}">${r.severity}</span>` : '');

function locationLine(r: RepoFinding): string {
  if (r.packageName) {
    const vulns = r.vulnIds?.length ? ` · ${r.vulnIds.map(esc).join(', ')}` : '';
    const fix = r.fixedVersion ? ` · fix in ${esc(r.fixedVersion)}+` : '';
    return `<div class="loc">${esc(r.packageName)}@${esc(r.packageVersion ?? '')}${vulns}${fix}</div>`;
  }
  if (!r.file) return '';
  const line = r.line !== undefined ? `:${r.line}` : '';
  const rule = r.ruleId ? ` · ${esc(r.ruleId)}` : '';
  const preview = r.preview ? ` · <code>${esc(r.preview)}</code>` : '';
  return `<div class="loc">${esc(r.file)}${line}${rule}${preview}</div>`;
}

export function renderRepoReport(scan: RepoScanOutput, score: Score): string {
  const fails = scan.results.filter((r) => r.status === 'fail').sort((a, b) => b.severity.localeCompare(a.severity));
  const errors = scan.results.filter((r) => r.status === 'error');
  const passes = scan.results.filter((r) => r.status === 'pass');

  const row = (r: RepoFinding, showFix: boolean) => `
    <div class="finding ${r.status}">
      <div class="finding-head">${statusBadge(r)} <strong>${esc(r.name)}</strong>${sevTag(r)}</div>
      <div class="detail">${esc(r.detail)}</div>
      ${locationLine(r)}
      ${showFix && r.fix ? `<div class="fix"><span class="fix-label">Fix →</span> <code>${esc(r.fix)}</code></div>` : ''}
    </div>`;

  const dialColor = score.grade === 'A' ? '#22c55e' : score.grade === 'B' ? '#84cc16' : score.grade === 'C' ? '#eab308' : score.grade === 'D' ? '#f97316' : '#ef4444';
  const base = scan.target.split('/').filter(Boolean).pop() ?? scan.target;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sitevitals repo · ${esc(base)} · ${score.score}/100</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; }
  .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
  .score-row { display: flex; align-items: center; gap: 1.5rem; }
  .dial { width: 96px; height: 96px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.75rem; font-weight: 700; color: #fff; background: ${dialColor}; }
  .meta { color: #6b7280; font-size: .85rem; }
  h2 { font-size: 1.1rem; margin: 1.5rem 0 .5rem; }
  .finding { border: 1px solid #e5e7eb; border-radius: 8px; padding: .75rem 1rem; margin-bottom: .5rem; }
  .finding.pass { opacity: .85; }
  .finding.fail { border-left: 4px solid #ef4444; }
  .finding.error { border-left: 4px solid #9ca3af; }
  .finding-head { margin-bottom: .25rem; }
  .sev { font-size: .7rem; text-transform: uppercase; padding: .1rem .4rem; border-radius: 999px; color: #fff; }
  .sev.high { background: #ef4444; } .sev.medium { background: #f59e0b; } .sev.low { background: #6b7280; }
  .detail { font-size: .9rem; }
  .loc { font-size: .85rem; color: #6b7280; margin-top: .25rem; }
  .fix { margin-top: .4rem; font-size: .85rem; background: #f9fafb; border-radius: 6px; padding: .5rem .75rem; }
  .fix-label { font-weight: 600; color: #059669; }
  code { font-family: ui-monospace, monospace; }
  footer { margin-top: 2rem; font-size: .8rem; color: #9ca3af; }
  details.passes summary { cursor: pointer; color: #6b7280; }
</style>
</head>
<body>
  <div class="card">
    <div class="score-row">
      <div class="dial">${score.score}</div>
      <div>
        <h1 style="margin:0">Grade ${score.grade}</h1>
        <div class="meta">${esc(scan.target)} · scanned ${esc(scan.scannedAt.replace('T', ' ').slice(0, 19))} UTC<br>
        ${score.passed} passed · ${score.failed} failed · ${score.errors} errors · ${scan.filesScanned} files scanned${scan.filesSkipped ? `, ${scan.filesSkipped} skipped` : ''}${scan.hitFileCap ? ' · FILE CAP HIT' : ''} · report only, no fixes applied</div>
      </div>
    </div>
  </div>

  ${fails.length ? `<h2>Findings (${fails.length})</h2>` + fails.map((r) => row(r, true)).join('') : '<h2>No failing findings 🎉</h2>'}
  ${errors.length ? `<h2>Could not run (${errors.length})</h2>` + errors.map((r) => row(r, false)).join('') : ''}
  <details class="passes"><summary>Passed checks (${passes.length})</summary>${passes.map((r) => row(r, false)).join('')}</details>

  <footer>Generated by sitevitals repo scan — report only. Findings never print a secret value (rule id + file + line + redacted preview). No live verification of found secrets is ever performed.</footer>
</body>
</html>`;
}
