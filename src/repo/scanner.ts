// scanner — walk a working tree (never git history), collect text files
// under caps. Skips node_modules/.git/dist and friends, symlinks, binaries
// and oversize files. Loud validation: a missing path or a non-directory
// is an error, never a silent empty scan.
import fs from 'node:fs';
import path from 'node:path';
import { ScannedFile } from './types.js';

export const MAX_FILES = 5000;
export const MAX_FILE_SIZE = 1_048_576; // 1 MiB per file
export const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', '.next', 'coverage', 'vendor']);

export interface CollectResult {
  files: ScannedFile[];
  /** Oversize / binary / unreadable files skipped. */
  skippedFiles: number;
  skippedDirs: string[];
  hitFileCap: boolean;
}

export function resolveRepoRoot(raw: string): string {
  const input = raw.trim();
  if (!input) throw new Error('No repo path given. Usage: node dist/cli.js repo <path> [--json]');
  const root = path.resolve(input);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(root);
  } catch {
    throw new Error(`Repo path does not exist: ${raw}`);
  }
  if (!stat.isDirectory()) throw new Error(`Repo path is not a directory: ${raw}`);
  return root;
}

function isBinary(buf: Buffer): boolean {
  // NUL byte in the first 8 KiB is a reliable binary tell for our purposes.
  return buf.subarray(0, 8192).includes(0);
}

export function collectFiles(root: string, opts?: { maxFiles?: number; maxFileSize?: number }): CollectResult {
  const maxFiles = opts?.maxFiles ?? MAX_FILES;
  const maxFileSize = opts?.maxFileSize ?? MAX_FILE_SIZE;
  const files: ScannedFile[] = [];
  const skippedDirs: string[] = [];
  let skippedFiles = 0;
  let hitFileCap = false;

  const walk = (dir: string): void => {
    if (files.length >= maxFiles) {
      hitFileCap = true;
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      skippedFiles++;
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (files.length >= maxFiles) {
        hitFileCap = true;
        return;
      }
      const absPath = path.join(dir, entry.name);
      const relPath = path.relative(root, absPath).split(path.sep).join('/');
      if (entry.isSymbolicLink()) {
        skippedFiles++;
        continue;
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          skippedDirs.push(relPath);
          continue;
        }
        walk(absPath);
        continue;
      }
      if (!entry.isFile()) {
        skippedFiles++;
        continue;
      }
      let stat: fs.Stats;
      try {
        stat = fs.statSync(absPath);
      } catch {
        skippedFiles++;
        continue;
      }
      if (stat.size > maxFileSize) {
        skippedFiles++;
        continue;
      }
      let buf: Buffer;
      try {
        buf = fs.readFileSync(absPath);
      } catch {
        skippedFiles++;
        continue;
      }
      if (isBinary(buf)) {
        skippedFiles++;
        continue;
      }
      files.push({ relPath, absPath, content: buf.toString('utf8') });
    }
  };

  walk(root);
  return { files, skippedFiles, skippedDirs, hitFileCap };
}
