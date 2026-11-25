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

function parseLockfile(content: string): { name: string; version: string }[] {
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
    .map(([name, version]) => ({ name, version }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

async function queryOsv(packages: { name: string; version: string }[]): Promise<OsvQueryResponse> {
  let res: Response;
  try {
    res = await fetch(OSV_QUERYBATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: packages.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })),
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
        if (ev.fixed && (!best || compareSemver(ev.fixed, best) > 0)) best = ev.fixed;
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
  cleanDetail: (filesScanned: number) => `No known-vulnerable npm dependencies in ${filesScanned} file(s).`,
  async run(files: ScannedFile[], ctx: RepoCheckContext): Promise<RepoFinding[]> {
    const lockfile = files.find((f) => f.relPath === 'package-lock.json');
    if (!lockfile) {
      return [
        {
          id: 'deps-no-lockfile',
          name: 'Dependencies',
          status: 'pass',
          severity: 'low',
          detail: 'No package-lock.json at the repo root — nothing to check (npm only in this slice).',
        },
      ];
    }
    if (ctx.allowlist.isAllowed(lockfile.relPath, 'deps-vulnerable')) {
      return [
        {
          id: 'deps-allowlisted',
          name: 'Dependencies',
          status: 'pass',
          severity: 'low',
          detail: 'package-lock.json is allowlisted — deps check skipped for it.',
        },
      ];
    }
    const packages = parseLockfile(lockfile.content);
    if (packages.length === 0) {
      return [
        {
          id: 'deps-no-deps',
          name: 'Dependencies',
          status: 'pass',
          severity: 'low',
          detail: 'package-lock.json has no dependencies to check.',
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
          `OSV fixture has ${resultCount} result(s) for ${packages.length} querie(s) (${packages.map((p) => `${p.name}@${p.version}`).join(', ')}). A querybatch fixture must have one result per queried package, in query order.`,
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
      findings.push({
        id: 'deps-vulnerable',
        name: 'Vulnerable dependency',
        status: 'fail',
        severity,
        detail: `${pkg.name}@${pkg.version} has ${vulns.length} known ${vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'}: ${withAliases.join(', ')}.`,
        fix: fixed
          ? `Upgrade ${pkg.name} to ${fixed} or later (fixes all listed vulnerabilities).`
          : `At least one listed vulnerability for ${pkg.name} has no published fix yet — check the advisories and upgrade when fixes land.`,
        packageName: pkg.name,
        packageVersion: pkg.version,
        fixedVersion: fixed,
        vulnIds: ids,
      });
    });
    return findings;
  },
};
