// sbom — CycloneDX-ish software bill of materials for a scanned repo.
// `sitevitals repo <path> --sbom` prints the inventory as pure JSON
// (or writes it with --sbom-out <file>). No scoring impact: it does not
// run the checks, it only inventories what the manifests declare.
// Components come from the same parsers the deps/license checks use
// (package-lock.json, requirements.txt, Pipfile.lock, go.mod), so the
// SBOM and the findings always agree about what is in the repo.
// "CycloneDX-ish" on purpose: the shape follows CycloneDX 1.5
// (bomFormat/specVersion/metadata/components, purl bom-refs) but this is
// not a validated CycloneDX generator — licenses are included only
// where the manifest declares them (npm), and PyPI/Go entries carry no
// license because their manifests do not declare one.
import path from 'node:path';
import { ScannedFile } from './types.js';
import { parseLockfile, parseRequirementsTxt, parsePipfileLock, parseGoMod, DepPackage } from './checks/deps.js';
import { parseLockfileLicenses } from './checks/licenses.js';

export interface SbomComponent {
  type: 'library';
  'bom-ref': string;
  name: string;
  version: string;
  purl: string;
  licenses?: { license: { id: string } | { name: string } }[];
}

export interface Sbom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  version: 1;
  metadata: {
    timestamp: string;
    tools: { vendor: string; name: string; version: string }[];
    component: { type: 'application'; 'bom-ref': string; name: string; version?: string };
  };
  components: SbomComponent[];
}

/** purl-encode the name part: @ and / are percent-encoded per the purl spec. */
function purlName(ecosystem: string, name: string): string {
  if (ecosystem === 'npm') return name.replace(/@/g, '%40').replace(/\//g, '%2F');
  return name;
}

function toPurl(pkg: DepPackage): string {
  const prefix = pkg.ecosystem === 'npm' ? 'pkg:npm' : pkg.ecosystem === 'PyPI' ? 'pkg:pypi' : 'pkg:golang';
  return `${prefix}/${purlName(pkg.ecosystem, pkg.name)}@${pkg.version}`;
}

/** A single-token SPDX-ish id goes in `id`; anything else in `name`. */
function licenseEntry(license: string): { license: { id: string } | { name: string } } {
  return /^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(license) && !license.includes('/')
    ? { license: { id: license } }
    : { license: { name: license } };
}

export function buildSbom(root: string, files: ScannedFile[], toolVersion = '1.0.0'): Sbom {
  const byKey = new Map<string, SbomComponent>();
  const add = (pkg: DepPackage, license?: string) => {
    const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
    if (byKey.has(key)) return;
    const purl = toPurl(pkg);
    byKey.set(key, {
      type: 'library',
      'bom-ref': purl,
      name: pkg.name,
      version: pkg.version,
      purl,
      ...(license ? { licenses: [licenseEntry(license)] } : {}),
    });
  };

  const lockfile = files.find((f) => f.relPath === 'package-lock.json');
  if (lockfile) {
    const licenses = parseLockfileLicenses(lockfile.content);
    for (const pkg of parseLockfile(lockfile.content)) {
      add(pkg, licenses.get(pkg.name)?.license);
    }
  }
  const requirements = files.find((f) => f.relPath === 'requirements.txt');
  if (requirements) for (const pkg of parseRequirementsTxt(requirements.content)) add(pkg);
  const pipfile = files.find((f) => f.relPath === 'Pipfile.lock');
  if (pipfile) for (const pkg of parsePipfileLock(pipfile.content)) add(pkg);
  const gomod = files.find((f) => f.relPath === 'go.mod');
  if (gomod) for (const pkg of parseGoMod(gomod.content)) add(pkg);

  const components = [...byKey.values()].sort((a, b) =>
    a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0,
  );

  // Root project identity, from package.json when present.
  let projectName = path.basename(root) || 'repo';
  let projectVersion: string | undefined;
  const pkgJson = files.find((f) => f.relPath === 'package.json');
  if (pkgJson) {
    try {
      const parsed = JSON.parse(pkgJson.content) as { name?: unknown; version?: unknown };
      if (typeof parsed.name === 'string' && parsed.name) projectName = parsed.name;
      if (typeof parsed.version === 'string' && parsed.version) projectVersion = parsed.version;
    } catch {
      // A broken package.json does not fail the SBOM; the name falls back.
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'SiteVitals', name: 'sitevitals', version: toolVersion }],
      component: {
        type: 'application',
        'bom-ref': projectName,
        name: projectName,
        ...(projectVersion ? { version: projectVersion } : {}),
      },
    },
    components,
  };
}
