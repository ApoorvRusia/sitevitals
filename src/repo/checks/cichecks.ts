// ci-config — GitHub Actions workflow hygiene in .github/workflows/.
// Two checks, both line-based (no YAML dependency — zero runtime deps):
// unpinned actions (uses: owner/repo@<not-a-40-hex-sha>) and over-broad
// top-level permissions (write-all, or any top-level write grant).
// Job-level permissions are scoped and are not flagged. Report-only.
import { RepoCheckModule, RepoFinding, RepoCheckContext, ScannedFile } from '../types.js';

const WORKFLOW_RE = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;
const SHA_RE = /^[0-9a-f]{40}$/;

/** Indent (leading spaces) of a line; tabs count as 2. */
function indentOf(line: string): number {
  let n = 0;
  for (const ch of line) {
    if (ch === ' ') n++;
    else if (ch === '\t') n += 2;
    else break;
  }
  return n;
}

export const ciConfigCheck: RepoCheckModule = {
  id: 'ci-config',
  name: 'CI config',
  cleanDetail: (filesScanned: number) => `No CI config issues in ${filesScanned} file(s).`,
  run(files: ScannedFile[], ctx: RepoCheckContext): RepoFinding[] {
    const findings: RepoFinding[] = [];
    for (const file of files) {
      if (!WORKFLOW_RE.test(file.relPath)) continue;
      const lines = file.content.split('\n');
      // Track a top-level `permissions:` block (indent 0) and its entries.
      let permIndent: number | undefined;
      let permEntries: { scope: string; level: string; line: number }[] = [];
      const flushPermissions = () => {
        if (permIndent === undefined) return;
        const writes = permEntries.filter((e) => e.level === 'write');
        if (writes.length > 0 && !ctx.allowlist.isAllowed(file.relPath, 'ci-permissions-write')) {
          const scopes = writes.map((w) => `${w.scope}: ${w.level}`).join(', ');
          findings.push({
            id: 'ci-permissions-write',
            name: 'Over-broad workflow permissions',
            status: 'fail',
            severity: 'medium',
            detail: `Top-level permissions grant write access (${scopes}) to every job — a compromised step gets write access to the whole repo.`,
            fix: 'Scope permissions to the jobs that need them (move permissions: under the job), and grant only the scopes each job needs, or drop the top-level block to inherit the read-only default.',
            file: file.relPath,
            ruleId: 'ci-permissions-write',
          });
        }
        permIndent = undefined;
        permEntries = [];
      };
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const indent = indentOf(raw);
        // Leaving a top-level permissions block ends it.
        if (permIndent !== undefined && indent <= permIndent && !/^permissions\s*:/.test(line)) flushPermissions();

        // Top-level `permissions:` — inline or block form.
        if (indent === 0 && /^permissions\s*:/.test(line)) {
          const inline = line.split(':').slice(1).join(':').trim();
          if (inline === 'write-all') {
            if (!ctx.allowlist.isAllowed(file.relPath, 'ci-permissions-write-all')) {
              findings.push({
                id: 'ci-permissions-write-all',
                name: 'Workflow permissions: write-all',
                status: 'fail',
                severity: 'high',
                detail: 'Top-level permissions: write-all grants every permission to every job.',
                fix: 'Remove permissions: write-all; grant only the scopes each job needs, at the job level.',
                file: file.relPath,
                line: i + 1,
                ruleId: 'ci-permissions-write-all',
              });
            }
            continue;
          }
          if (inline === '' || inline === '{}') {
            permIndent = indent;
            permEntries = [];
            continue;
          }
          // Inline map form, e.g. permissions: {contents: write} — rare;
          // judge it as a top-level grant.
          const writes = [...inline.matchAll(/([A-Za-z0-9_-]+)\s*:\s*write\b/g)].map((m) => m[1]);
          if (writes.length > 0 && !ctx.allowlist.isAllowed(file.relPath, 'ci-permissions-write')) {
            findings.push({
              id: 'ci-permissions-write',
              name: 'Over-broad workflow permissions',
              status: 'fail',
              severity: 'medium',
              detail: `Top-level permissions grant write access (${writes.map((w) => `${w}: write`).join(', ')}) to every job.`,
              fix: 'Scope permissions to the jobs that need them (move permissions: under the job), and grant only the scopes each job needs.',
              file: file.relPath,
              line: i + 1,
              ruleId: 'ci-permissions-write',
            });
          }
          continue;
        }

        // Inside a top-level permissions block: `scope: level` entries.
        if (permIndent !== undefined && indent > permIndent) {
          const m = /^([A-Za-z0-9_-]+)\s*:\s*(read|write|none)\s*(?:#.*)?$/.exec(line);
          if (m) permEntries.push({ scope: m[1], level: m[2], line: i + 1 });
          continue;
        }

        // Unpinned actions: uses: owner/repo@<ref> (not a local ./ action,
        // not a docker:// image). Pinned = a full 40-hex commit SHA.
        const uses = /^\s*-\s*uses\s*:\s*([^\s#]+)/.exec(raw) ?? /^\s*uses\s*:\s*([^\s#]+)/.exec(raw);
        if (uses) {
          const ref = uses[1].replace(/^['"]|['"]$/g, '');
          if (ref.startsWith('./') || ref.startsWith('docker://')) continue;
          const at = ref.lastIndexOf('@');
          // No @ref at all means the default branch — also unpinned.
          const pinned = at >= 0 && SHA_RE.test(ref.slice(at + 1));
          if (!pinned && !ctx.allowlist.isAllowed(file.relPath, 'ci-unpinned-action')) {
            findings.push({
              id: 'ci-unpinned-action',
              name: 'Unpinned GitHub Action',
              status: 'fail',
              severity: 'medium',
              detail:
                at < 0
                  ? `Action ${ref} has no ref — it resolves to the default branch, which can move to different code.`
                  : `Action ${ref} is pinned to a tag/branch, not a commit SHA — the tag can be moved to different code.`,
              fix: `Pin ${ref.split('@')[0]} to the full commit SHA of the release (e.g. uses: ${ref.split('@')[0]}@<40-hex-sha>).`,
              file: file.relPath,
              line: i + 1,
              ruleId: 'ci-unpinned-action',
            });
          }
        }
      }
      flushPermissions();
    }
    return findings;
  },
};
