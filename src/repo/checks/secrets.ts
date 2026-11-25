// secrets — vendored Gitleaks default rules (MIT, attributed; see
// src/repo/rules/secrets.json) matched line-by-line over the collected
// working tree. No shell-outs, no live verification of found secrets —
// ever. Reports carry rule id + file + line + REDACTED preview only:
// the secret value never leaves this module.
import fs from 'node:fs';
import path from 'node:path';
import { RepoCheckModule, RepoFinding, RepoCheckContext, ScannedFile, Severity } from '../types.js';

interface SecretRule {
  id: string;
  name: string;
  severity: Severity;
  pattern: string;
  flags?: string;
  group?: number;
  generic?: boolean;
  description: string;
  fix: string;
}

let cachedRules: { rule: SecretRule; re: RegExp }[] | null = null;

function loadRules(): { rule: SecretRule; re: RegExp }[] {
  if (cachedRules) return cachedRules;
  const here = __dirname;
  // dist/repo/checks/secrets.js → dist/repo/rules/secrets.json (copied
  // there by `npm run build`); fall back to the source tree.
  const candidates = [
    path.join(here, '..', 'rules', 'secrets.json'),
    path.join(here, '..', '..', '..', 'src', 'repo', 'rules', 'secrets.json'),
  ];
  const found = candidates.find((p) => fs.existsSync(p));
  if (!found) {
    throw new Error(`Secrets rule file not found (looked in: ${candidates.join(', ')}). Run \`npm run build\` first.`);
  }
  const parsed = JSON.parse(fs.readFileSync(found, 'utf8')) as { rules?: SecretRule[] };
  if (!Array.isArray(parsed.rules) || parsed.rules.length === 0) {
    throw new Error(`Secrets rule file has no rules: ${found}`);
  }
  cachedRules = parsed.rules.map((rule) => {
    let re: RegExp;
    try {
      re = new RegExp(rule.pattern, `g${rule.flags ?? ''}`);
    } catch (err) {
      throw new Error(`Secrets rule "${rule.id}" has an invalid pattern: ${(err as Error).message}`);
    }
    return { rule, re };
  });
  return cachedRules;
}

/** Redact a matched secret: first 4 chars + marker, never the value. */
export function redactSecret(value: string): string {
  if (value.length <= 4) return '…[redacted]';
  return `${value.slice(0, 4)}…[redacted]`;
}

function isPlaceholder(value: string): boolean {
  if (/^(.)\1+$/.test(value)) return true;
  if (/^(example|placeholder|changeme|your-|test|xxx|dummy)/i.test(value)) return true;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
  return classes < 2 && value.length < 24;
}

export const secretsCheck: RepoCheckModule = {
  id: 'secrets',
  name: 'Secrets',
  cleanDetail: (filesScanned: number) => `No secrets found in ${filesScanned} file(s).`,
  run(files: ScannedFile[], ctx: RepoCheckContext): RepoFinding[] {
    const rules = loadRules();
    const findings: RepoFinding[] = [];
    const seen = new Set<string>();

    for (const file of files) {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let lineFlaggedBySpecific = false;
        for (const { rule, re } of rules) {
          // Generic rules skip lines a specific rule already flagged.
          if (rule.generic && lineFlaggedBySpecific) continue;
          re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = re.exec(line)) !== null) {
            const secret = m[rule.group ?? 0] ?? m[0];
            if (!secret) break;
            if (rule.generic && isPlaceholder(secret)) continue;
            if (ctx.allowlist.isAllowed(file.relPath, rule.id)) continue;
            const key = `${file.relPath}:${i + 1}:${rule.id}:${secret}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({
              id: rule.id,
              name: rule.name,
              status: 'fail',
              severity: rule.severity,
              detail: `${rule.name} found (${rule.id}). ${rule.description} Rotate it and remove it from the repo.`,
              fix: rule.fix,
              file: file.relPath,
              line: i + 1,
              ruleId: rule.id,
              preview: redactSecret(secret),
            });
            if (!rule.generic) lineFlaggedBySpecific = true;
            if (m[0].length === 0) break; // empty match: avoid an infinite loop
          }
        }
      }
    }
    return findings;
  },
};
