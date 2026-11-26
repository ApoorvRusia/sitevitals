// licenses — dependency license audit from package-lock.json (npm).
// Flags copyleft licenses (GPL/AGPL/LGPL in any form) and unknown or
// missing licenses, one finding per package. Report-only: it judges
// the license field as published, it does not fetch license texts and
// it is not legal advice — a flagged package needs a human to read the
// actual license. Only the root package-lock.json is read (same file
// the deps check uses); PyPI/Go license data is not in their manifests,
// so those ecosystems are out of scope for this check.
import { RepoCheckModule, RepoFinding, RepoCheckContext, ScannedFile } from '../types.js';

const COPYLEFT_RE = /\b(?:a?gpl|lgpl)\b/i;

function licenseOf(entry: { license?: unknown; licenses?: unknown }): string | undefined {
  if (typeof entry.license === 'string' && entry.license.trim()) return entry.license.trim();
  if (Array.isArray(entry.licenses)) {
    const types = entry.licenses
      .map((l) => (l as { type?: unknown })?.type)
      .filter((t): t is string => typeof t === 'string' && !!t.trim());
    if (types.length > 0) return types.join(' / ');
  }
  return undefined;
}

export const licensesCheck: RepoCheckModule = {
  id: 'licenses',
  name: 'Dependency licenses',
  cleanDetail: (filesScanned: number) => `No copyleft or unknown-license dependencies in ${filesScanned} file(s).`,
  run(files: ScannedFile[], ctx: RepoCheckContext): RepoFinding[] {
    const lockfile = files.find((f) => f.relPath === 'package-lock.json');
    if (!lockfile) {
      return [
        {
          id: 'licenses-no-lockfile',
          name: 'Dependency licenses',
          status: 'pass',
          severity: 'low',
          detail: 'No package-lock.json at the repo root — nothing to audit (npm only in this check).',
        },
      ];
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(lockfile.content);
    } catch {
      throw new Error('package-lock.json is not valid JSON.');
    }
    const obj = parsed as { packages?: Record<string, { version?: string; license?: unknown; licenses?: unknown }>; dependencies?: Record<string, { version?: string; license?: unknown; licenses?: unknown }> };
    const entries = new Map<string, { version?: string; license?: string }>();
    const collect = (key: string, entry: { version?: string; license?: unknown; licenses?: unknown }) => {
      const m = key.match(/^node_modules\/(@[^/]+\/[^/]+|[^/]+)$/);
      if (!m || entries.has(m[1])) return;
      entries.set(m[1], { version: entry.version, license: licenseOf(entry) });
    };
    if (obj.packages && typeof obj.packages === 'object') {
      for (const key of Object.keys(obj.packages).sort()) {
        if (key === '') continue; // the project itself, not a dependency
        collect(key, obj.packages[key]);
      }
    }
    if (obj.dependencies && typeof obj.dependencies === 'object') {
      for (const name of Object.keys(obj.dependencies).sort()) {
        const entry = obj.dependencies[name];
        if (!entries.has(name)) entries.set(name, { version: entry.version, license: licenseOf(entry) });
      }
    }

    const findings: RepoFinding[] = [];
    for (const [name, { version, license }] of [...entries.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      const label = `${name}@${version ?? '?'}`;
      // UNLICENSED (proprietary, no reuse rights) and SEE LICENSE IN
      // (terms live in a file we cannot judge) are unknowns, not passes.
      const unknown = !license || /^unlicensed$/i.test(license) || /^see license in\b/i.test(license);
      if (unknown) {
        if (ctx.allowlist.isAllowed(lockfile.relPath, 'license-unknown')) continue;
        findings.push({
          id: 'license-unknown',
          name: 'Unknown dependency license',
          status: 'fail',
          severity: 'low',
          detail: license
            ? `${label} publishes license "${license}" — its terms cannot be judged from the lockfile, so redistributing or shipping it is a legal unknown.`
            : `${label} publishes no license in package-lock.json — its terms are unknown, so redistributing or shipping it is a legal unknown.`,
          fix: `Check ${name}'s registry page / repository for its license; if it has none, replace it or get the terms in writing from the author.`,
          file: lockfile.relPath,
          ruleId: 'license-unknown',
          packageName: name,
          packageVersion: version,
        });
        continue;
      }
      if (COPYLEFT_RE.test(license)) {
        if (ctx.allowlist.isAllowed(lockfile.relPath, 'license-copyleft')) continue;
        findings.push({
          id: 'license-copyleft',
          name: 'Copyleft dependency license',
          status: 'fail',
          severity: 'medium',
          detail: `${label} is licensed ${license} — copyleft terms can require sharing source of linked/combined work.`,
          fix: `Read the ${license} terms for ${name} and confirm they fit this project; if not, replace it with a permissively licensed alternative.`,
          file: lockfile.relPath,
          ruleId: 'license-copyleft',
          packageName: name,
          packageVersion: version,
        });
      }
    }
    return findings;
  },
};
