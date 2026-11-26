// deps — npm dependency vulnerability check via OSV.dev (free, no key).
// Two steps, because that is how OSV works: POST /v1/querybatch returns
// only minimal vuln records ({id, modified}) for each package@version,
// and the full record (aliases, severity, affected ranges with fixed
// versions) comes from GET /v1/vulns/<id>. Only package names + versions
// leave the machine — never code. Parses the root package-lock.json
// (lockfileVersion 2/3; legacy `dependencies` map also read). OSV failure
// is an `error`, never a `fail`. --osv-fixture runs the check against
// recorded responses instead of the network — that is how it is verified
// in sandboxes without egress; the fixture is a wrapper holding both
// recorded steps ({querybatch, details}) and the live HTTP path below is
// used whenever no fixture is given.
import fs from 'node:fs';
import path from 'node:path';
import { RepoCheckModule, RepoFinding, RepoCheckContext, ScannedFile } from '../types.js';

const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const OSV_TIMEOUT_MS = 30_000;

/** One dependency to query: name + pinned version + ecosystem + source file. */
export interface DepPackage {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI' | 'Go';
  /** Manifest rel path the package came from (for finding context). */
  source: string;
}

interface OsvQueryVuln {
  id: string;
  modified?: string;
}

interface OsvQueryResponse {
  results?: { vulns?: OsvQueryVuln[] }[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    ranges?: { type: string; events: { introduced?: string; fixed?: string; limit?: string }[] }[];
  }[];
}

interface OsvFixture {
  querybatch: OsvQueryResponse;
  details: Record<string, OsvVuln>;
}

/** Minimal semver compare (numeric segments; prerelease suffix ignored). */
export function compareSemver(a: string, b: string): number {
  const pa = a.split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function parseLockfile(content: string): DepPackage[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error('package-lock.json is not valid JSON.');
  }
  const found = new Map<string, string>();
  const obj = parsed as { packages?: Record<string, { version?: string }>; dependencies?: Record<string, { version?: string }> };
  if (obj.packages && typeof obj.packages === 'object') {
    const keys = Object.keys(obj.packages).sort();
    for (const key of keys) {
      // Root entry ("") is the project itself, not a dependency.
      if (key === '') continue;
      // "node_modules/<name>" — nested paths ("node_modules/a/node_modules/b")
      // belong to a nested copy; first (shallowest) occurrence wins.
      const m = key.match(/^node_modules\/(@[^/]+\/[^/]+|[^/]+)$/);
      if (!m) continue;
      const name = m[1];
      const version = obj.packages[key].version;
      if (version && !found.has(name)) found.set(name, version);
    }
  }
  if (obj.dependencies && typeof obj.dependencies === 'object') {
    for (const name of Object.keys(obj.dependencies).sort()) {
      const version = obj.dependencies[name].version;
      if (version && !found.has(name)) found.set(name, version);
    }
  }
  return [...found.entries()]
    .map(([name, version]) => ({ name, version, ecosystem: 'npm' as const, source: 'package-lock.json' }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

/**
 * requirements.txt — pinned versions only. A line counts only when it
 * pins an exact version (`name==1.2.3` or `name===1.2.3`, extras and
 * environment markers stripped). Unpinned lines (`>=`, `~=`, `>`,
 * `-r` includes, options) are skipped silently — they are not findings
 * and not queries; the file cannot tell us which version is installed.
 */
export function parseRequirementsTxt(content: string): DepPackage[] {
  const found = new Map<string, string>();
  for (const raw of content.split('\n')) {
    let line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    // Strip an inline comment ("name==1.2.3  # pinned") and markers.
    const hash = line.indexOf(' #');
    if (hash >= 0) line = line.slice(0, hash).trim();
    const semi = line.indexOf(';');
    if (semi >= 0) line = line.slice(0, semi).trim();
    const m = /^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:===|==)\s*([^\s,]+)/.exec(line);
    if (!m) continue; // unpinned / option / URL line: skip, not a finding
    const name = m[1].toLowerCase();
    const version = m[2].replace(/^['"]|['"]$/g, '');
    if (version && !found.has(name)) found.set(name, version);
  }
  return [...found.entries()]
    .map(([name, version]) => ({ name, version, ecosystem: 'PyPI' as const, source: 'requirements.txt' }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

/**
 * Pipfile.lock — `default` + `develop` maps; each entry pins via
 * `"version": "==1.2.3"`. Entries without a pinned version (editable
 * installs, git refs) are skipped, same rule as requirements.txt.
 */
export function parsePipfileLock(content: string): DepPackage[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error('Pipfile.lock is not valid JSON.');
  }
  const found = new Map<string, string>();
  const obj = parsed as { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
  for (const section of ['default', 'develop'] as const) {
    const map = obj[section];
    if (!map || typeof map !== 'object') continue;
    for (const name of Object.keys(map).sort()) {
      const v = map[name]?.version;
      if (typeof v !== 'string' || !v.startsWith('==')) continue;
      const version = v.slice(2).trim();
      const key = name.toLowerCase();
      if (version && !found.has(key)) found.set(key, version);
    }
  }
  return [...found.entries()]
    .map(([name, version]) => ({ name, version, ecosystem: 'PyPI' as const, source: 'Pipfile.lock' }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

/**
 * go.mod — `require` blocks and single-line requires. Each requirement
 * is `module/path vX.Y.Z` (the `v` prefix is part of the Go version and
 * is what OSV expects). `// indirect` comments are stripped; `replace`,
 * `exclude`, `retract` and the `go`/`module` directives are not
 * requirements and are skipped.
 */
export function parseGoMod(content: string): DepPackage[] {
  const found = new Map<string, string>();
  let inRequireBlock = false;
  for (const raw of content.split('\n')) {
    let line = raw.trim();
    if (!line) continue;
    const comment = line.indexOf('//');
    if (comment >= 0) line = line.slice(0, comment).trim();
    if (!line) continue;
    if (line === 'require (') {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ')') {
      inRequireBlock = false;
      continue;
    }
    let req: string | undefined;
    if (inRequireBlock) req = line;
    else if (line.startsWith('require ')) req = line.slice('require '.length).trim();
    else continue;
    if (!req) continue;
    const parts = req.split(/\s+/);
    if (parts.length < 2) continue;
    const [name, version] = parts;
    if (!/^v\d/.test(version)) continue; // not a versioned requirement
    if (!found.has(name)) found.set(name, version);
  }
  return [...found.entries()]
    .map(([name, version]) => ({ name, version, ecosystem: 'Go' as const, source: 'go.mod' }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

/**
 * OSV Go `fixed` versions come back without the `v` prefix ("1.9.1"),
 * but `go get` needs it ("v1.9.1"). Display (and record) the prefixed
 * form for Go packages; every other ecosystem is shown as OSV gave it.
 */
function displayFixedVersion(pkg: DepPackage, fixed: string): string {
  if (pkg.ecosystem === 'Go' && !fixed.startsWith('v')) return `v${fixed}`;
  return fixed;
}

async function queryOsv(packages: DepPackage[]): Promise<OsvQueryResponse> {
  let res: Response;
  try {
    res = await fetch(OSV_QUERYBATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: packages.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
      }),
      signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`Could not reach OSV.dev (${(err as Error).message}). Check your network and re-run; this is not a vulnerability.`);
  }
  if (!res.ok) {
    throw new Error(`OSV.dev returned HTTP ${res.status}. Check your network and re-run; this is not a vulnerability.`);
  }
  return (await res.json()) as OsvQueryResponse;
}

async function fetchVulnDetail(id: string): Promise<OsvVuln> {
  const res = await fetch(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {
    signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`OSV.dev returned HTTP ${res.status} for ${id}.`);
  return (await res.json()) as OsvVuln;
}

function readFixture(fixturePath: string): OsvFixture {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  } catch (err) {
    throw new Error(`OSV fixture is not valid JSON (${fixturePath}): ${(err as Error).message}`);
  }
  const fixture = parsed as Partial<OsvFixture>;
  if (!fixture.querybatch || !Array.isArray(fixture.querybatch.results)) {
    throw new Error(`OSV fixture needs a "querybatch" object with a "results" array: ${fixturePath}`);
  }
  if (!fixture.details || typeof fixture.details !== 'object') {
    throw new Error(`OSV fixture needs a "details" object (vuln id -> full /v1/vulns record): ${fixturePath}`);
  }
  return fixture as OsvFixture;
}

function maxFixedVersion(vuln: OsvVuln): string | undefined {
  let best: string | undefined;
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events) {
        // Only version-shaped fixes count: some records list commit SHAs
        // as "fixed" (e.g. a 40-hex SHA starting with digits, which a
        // naive numeric compare would rank above real versions).
        if (ev.fixed && /^(v)?\d+\.\d+/.test(ev.fixed) && (!best || compareSemver(ev.fixed, best) > 0)) best = ev.fixed;
      }
    }
  }
  return best;
}

function vulnSeverity(vuln: OsvVuln): 'high' | 'medium' | 'low' {
  for (const s of vuln.severity ?? []) {
    const score = parseFloat(s.score);
    if (!Number.isNaN(score)) return score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
  }
  const label = (vuln.database_specific?.severity ?? '').toLowerCase();
  if (label === 'critical' || label === 'high') return 'high';
  if (label === 'moderate' || label === 'medium') return 'medium';
  return 'medium';
}

export const depsCheck: RepoCheckModule = {
  id: 'deps',
  name: 'Dependencies',
  cleanDetail: (filesScanned: number) => `No known-vulnerable dependencies in ${filesScanned} file(s).`,
  async run(files: ScannedFile[], ctx: RepoCheckContext): Promise<RepoFinding[]> {
    // Manifests are read in file order, but the query list is built
    // per ecosystem (npm, then PyPI, then Go), each sorted by name, so
    // the OSV query order — and any fixture — is deterministic
    // regardless of which manifest a package came from.
    const manifests: { relPath: string; parse: (content: string) => DepPackage[] }[] = [
      { relPath: 'package-lock.json', parse: parseLockfile },
      { relPath: 'requirements.txt', parse: parseRequirementsTxt },
      { relPath: 'Pipfile.lock', parse: parsePipfileLock },
      { relPath: 'go.mod', parse: parseGoMod },
    ];
    const byEcosystem = new Map<string, Map<string, DepPackage>>();
    let foundAnyManifest = false;
    let skippedAll = true;
    for (const m of manifests) {
      const file = files.find((f) => f.relPath === m.relPath);
      if (!file) continue;
      foundAnyManifest = true;
      if (ctx.allowlist.isAllowed(file.relPath, 'deps-vulnerable')) continue;
      skippedAll = false;
      for (const p of m.parse(file.content)) {
        let eco = byEcosystem.get(p.ecosystem);
        if (!eco) {
          eco = new Map();
          byEcosystem.set(p.ecosystem, eco);
        }
        if (!eco.has(p.name)) eco.set(p.name, p);
      }
    }
    const packages: DepPackage[] = [];
    for (const eco of ['npm', 'PyPI', 'Go'] as const) {
      const map = byEcosystem.get(eco);
      if (!map) continue;
      packages.push(...[...map.values()].sort((a, b) => (a.name < b.name ? -1 : 1)));
    }
    const ecosystems = new Set(packages.map((p) => p.ecosystem));
    if (!foundAnyManifest) {
      return [
        {
          id: 'deps-no-lockfile',
          name: 'Dependencies',
          status: 'pass',
          severity: 'low',
          detail: 'No dependency manifest at the repo root (package-lock.json, requirements.txt, Pipfile.lock, go.mod) — nothing to check.',
        },
      ];
    }
    if (skippedAll) {
      return [
        {
          id: 'deps-allowlisted',
          name: 'Dependencies',
          status: 'pass',
          severity: 'low',
          detail: 'All dependency manifests are allowlisted — deps check skipped.',
        },
      ];
    }
    if (packages.length === 0) {
      return [
        {
          id: 'deps-no-deps',
          name: 'Dependencies',
          status: 'pass',
          severity: 'low',
          detail: 'Dependency manifests have no pinned dependencies to check.',
        },
      ];
    }

    let query: OsvQueryResponse;
    let details: Record<string, OsvVuln>;
    if (ctx.osvFixture) {
      const fixture = readFixture(ctx.osvFixture);
      query = fixture.querybatch;
      details = fixture.details;
      const resultCount = query.results?.length ?? 0;
      if (resultCount !== packages.length) {
        throw new Error(
          `OSV fixture has ${resultCount} result(s) for ${packages.length} querie(s) (${packages.map((p) => `${p.name}@${p.version} (${p.ecosystem})`).join(', ')}). A querybatch fixture must have one result per queried package, in query order (npm, then PyPI, then Go; each sorted by name).`,
        );
      }
    } else {
      query = await queryOsv(packages);
      // Full records come from /v1/vulns/<id>, one per unique vuln id.
      // A failed detail fetch degrades to the minimal record (id only)
      // rather than failing the whole check.
      const ids = [...new Set((query.results ?? []).flatMap((r) => (r.vulns ?? []).map((v) => v.id)))];
      const settled = await Promise.allSettled(ids.map((id) => fetchVulnDetail(id)));
      details = {};
      settled.forEach((s, i) => {
        details[ids[i]] = s.status === 'fulfilled' ? s.value : { id: ids[i] };
      });
    }

    const findings: RepoFinding[] = [];
    packages.forEach((pkg, i) => {
      const queryVulns = query.results?.[i]?.vulns ?? [];
      if (queryVulns.length === 0) return;
      const vulns = queryVulns.map((v) => details[v.id] ?? { id: v.id });
      const ids = vulns.map((v) => v.id);
      const withAliases = vulns.map((v) => (v.aliases?.length ? `${v.id} (${v.aliases.join(', ')})` : v.id));
      // Fix guidance only when EVERY listed vuln has a fixed version;
      // otherwise the "upgrade to X" claim would be wrong for the unfixed one.
      const fixedVersions = vulns.map(maxFixedVersion);
      const fixed = fixedVersions.every((f) => !!f)
        ? fixedVersions.reduce<string | undefined>((best, f) => (f && (!best || compareSemver(f, best) > 0) ? f : best), undefined)
        : undefined;
      const severity = vulns.some((v) => vulnSeverity(v) === 'high') ? 'high' : 'medium';
      const shownFixed = fixed ? displayFixedVersion(pkg, fixed) : undefined;
      findings.push({
        id: 'deps-vulnerable',
        name: 'Vulnerable dependency',
        status: 'fail',
        severity,
        detail: `${pkg.name}@${pkg.version} (${pkg.ecosystem}) has ${vulns.length} known ${vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'}: ${withAliases.join(', ')}.`,
        fix: shownFixed
          ? `Upgrade ${pkg.name} to ${shownFixed} or later (fixes all listed vulnerabilities).`
          : `At least one listed vulnerability for ${pkg.name} has no published fix yet — check the advisories and upgrade when fixes land.`,
        packageName: pkg.name,
        packageVersion: pkg.version,
        fixedVersion: shownFixed,
        vulnIds: ids,
        ecosystem: pkg.ecosystem,
      });
    });
    return findings;
  },
};
