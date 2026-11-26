// dockerfile — Dockerfile hygiene: root user, secrets in ENV/ARG
// layers, unpinned (:latest or untagged) base images. Report-only, like
// every repo check. Secrets in layers reuse the vendored secrets rules
// (same engine, same redaction) via scanLineForSecrets from secrets.ts
// — a credential in a layer is flagged by both modules, because it is
// both a leaked secret and a layer problem; the Dockerfile finding
// carries the redacted preview only, never the value.
import { RepoCheckModule, RepoFinding, RepoCheckContext, ScannedFile } from '../types.js';
import { redactSecret, scanLineForSecrets } from './secrets.js';

const DOCKERFILE_RE = /(?:^|\/)Dockerfile(?:\..*)?$/;

function parseFromImage(line: string): string | undefined {
  // FROM [--platform=...] <image> [AS <stage>]
  const rest = line.replace(/^FROM\s+/i, '').trim();
  if (!rest) return undefined;
  const tokens = rest.split(/\s+/).filter((t) => !t.startsWith('--platform='));
  return tokens[0];
}

function imageTagStatus(image: string): 'pinned' | 'latest' | 'implicit-latest' | 'unknown' {
  if (!image || image.startsWith('$')) return 'unknown'; // variable image: cannot tell
  if (image.includes('@')) return 'pinned'; // digest-pinned: image@sha256:...
  const name = image;
  if (name === 'scratch') return 'pinned';
  const lastSlash = name.lastIndexOf('/');
  const lastColon = name.lastIndexOf(':');
  if (lastColon <= lastSlash) return 'implicit-latest'; // no tag at all (a :port is not a tag)
  return name.slice(lastColon + 1) === 'latest' ? 'latest' : 'pinned';
}

export const dockerfileCheck: RepoCheckModule = {
  id: 'dockerfile',
  name: 'Dockerfile',
  cleanDetail: (filesScanned: number) => `No Dockerfile issues in ${filesScanned} file(s).`,
  run(files: ScannedFile[], ctx: RepoCheckContext): RepoFinding[] {
    const findings: RepoFinding[] = [];
    for (const file of files) {
      if (!DOCKERFILE_RE.test(file.relPath)) continue;
      const lines = file.content.split('\n');
      let hasUser = false;
      let userIsRoot = false;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;
        const upper = line.toUpperCase();
        if (upper.startsWith('USER ')) {
          const who = line.slice(5).trim().split(/\s+/)[0].toLowerCase();
          hasUser = true;
          if (who === 'root' || who === '0' || who === '0:0') userIsRoot = true;
          continue;
        }
        if (upper.startsWith('FROM ')) {
          const image = parseFromImage(line);
          if (!image) continue;
          const status = imageTagStatus(image);
          if ((status === 'latest' || status === 'implicit-latest') && !ctx.allowlist.isAllowed(file.relPath, 'dockerfile-latest-tag')) {
            findings.push({
              id: 'dockerfile-latest-tag',
              name: 'Unpinned base image',
              status: 'fail',
              severity: 'medium',
              detail: `Base image ${image} uses the :latest tag${status === 'implicit-latest' ? ' (no tag means :latest)' : ''} — builds are not reproducible and a new upstream image can change behavior silently.`,
              fix: 'Pin the base image to a specific version (e.g. node:20.11.0) or a digest (image@sha256:...).',
              file: file.relPath,
              line: i + 1,
              ruleId: 'dockerfile-latest-tag',
            });
          }
          continue;
        }
        if (upper.startsWith('ENV ') || upper.startsWith('ARG ')) {
          if (ctx.allowlist.isAllowed(file.relPath, 'dockerfile-secret-env')) continue;
          for (const m of scanLineForSecrets(line)) {
            findings.push({
              id: 'dockerfile-secret-env',
              name: 'Secret in image layer',
              status: 'fail',
              severity: 'high',
              detail: `${m.name} (${m.ruleId}) in an ENV/ARG layer — it is baked into the image and visible to anyone who can pull it.`,
              fix: 'Pass secrets at runtime (secret mounts, --secret, or environment variables at run time), never in ENV/ARG.',
              file: file.relPath,
              line: i + 1,
              ruleId: 'dockerfile-secret-env',
              preview: redactSecret(m.secret),
            });
          }
        }
      }
      if ((!hasUser || userIsRoot) && !ctx.allowlist.isAllowed(file.relPath, 'dockerfile-root-user')) {
        findings.push({
          id: 'dockerfile-root-user',
          name: 'Container runs as root',
          status: 'fail',
          severity: 'medium',
          detail: !hasUser
            ? 'No USER instruction — the container runs as root by default.'
            : 'USER is root — the container runs as root.',
          fix: 'Add a non-root user and switch to it: RUN useradd -m app && USER app (or USER node for the official node image).',
          file: file.relPath,
          ruleId: 'dockerfile-root-user',
        });
      }
    }
    return findings;
  },
};
