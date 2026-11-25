// allowlist — `.sitevitals-allowlist.json` in the scanned repo root (or an
// explicit --allowlist path). Entries suppress findings for a file, or for
// one rule in a file. This is the ONLY way planted/test secrets (the
// test-harness TLS key, the fixture secrets) stay out of dogfood scans;
// it never suppresses a finding for a file outside the scanned tree, and
// a corrupt allowlist file is a loud error, never silently ignored.
import fs from 'node:fs';
import path from 'node:path';
import { Allowlist, AllowlistEntry } from './types.js';

export const ALLOWLIST_FILENAME = '.sitevitals-allowlist.json';

function matches(entryPath: string, relPath: string): boolean {
  const entry = entryPath.split(path.sep).join('/');
  if (entry.endsWith('/**')) {
    const prefix = entry.slice(0, -2); // keeps the trailing slash
    return relPath.startsWith(prefix);
  }
  return relPath === entry;
}

export function loadAllowlist(root: string, explicitPath?: string): Allowlist {
  const entries: AllowlistEntry[] = [];
  const candidates = explicitPath ? [path.resolve(explicitPath)] : [path.join(root, ALLOWLIST_FILENAME)];
  for (const p of candidates) {
    if (!fs.existsSync(p)) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    } catch {
      throw new Error(`Allowlist file is not valid JSON: ${p}`);
    }
    const list = (parsed as { entries?: unknown }).entries;
    if (!Array.isArray(list)) throw new Error(`Allowlist file has no "entries" array: ${p}`);
    for (const e of list) {
      const entry = e as Partial<AllowlistEntry>;
      if (typeof entry.path !== 'string' || typeof entry.reason !== 'string') {
        throw new Error(`Allowlist entry needs a string "path" and "reason": ${p}`);
      }
      entries.push({ path: entry.path, reason: entry.reason, rule: entry.rule });
    }
  }
  return {
    entries,
    isAllowed(relPath: string, ruleId?: string): boolean {
      // A finding is suppressed when an entry matches the path and either
      // the entry has no rule (whole file) or its rule matches. Called
      // without a rule id, only rule-less (whole-file) entries match.
      return entries.some(
        (e) => matches(e.path, relPath) && (ruleId === undefined ? !e.rule : !e.rule || e.rule === ruleId),
      );
    },
  };
}
