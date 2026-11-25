// injection — hand-written JS/TS regex patterns for common injection
// sinks (dynamic code execution, shell commands built from input, SQL
// string building, unsanitized HTML). No semgrep/opengrep shell-outs;
// AST/taint analysis is a later upgrade path. Report-only, like every
// repo check: a finding names the pattern + file + line and suggests a
// fix; nothing is changed.
//
// NOTE on self-matching: this file is itself scanned by the dogfood run,
// so pattern names/descriptions/fixes deliberately avoid the literal
// trigger sequences (e.g. the prose never spells out a call with its
// opening paren). The one pattern that would match its own literal —
// the React raw-HTML prop — is built by string concatenation for exactly
// that reason.
import { RepoCheckModule, RepoFinding, RepoCheckContext, ScannedFile, Severity } from '../types.js';

interface InjectionPattern {
  id: string;
  name: string;
  severity: Severity;
  pattern: RegExp;
  description: string;
  fix: string;
}

const RAW_HTML_PROP = 'dangerously' + 'SetInnerHTML';

const PATTERNS: InjectionPattern[] = [
  {
    id: 'eval-call',
    name: 'Dynamic code execution',
    severity: 'high',
    pattern: /\beval\s*\(/,
    description: 'Calling eval on a string executes it as code; with user input that is remote code execution.',
    fix: 'Replace dynamic code execution with a safe parser, a lookup table, or JSON.parse for data; never pass user input to eval.',
  },
  {
    id: 'function-constructor',
    name: 'Function constructor',
    severity: 'high',
    pattern: /new\s+Function\s*\(/,
    description: 'The Function constructor builds executable code from a string, just like eval.',
    fix: 'Replace the Function constructor with a normal function or a safe expression parser; never build code from user input.',
  },
  {
    id: 'exec-template',
    name: 'Shell command with template interpolation',
    severity: 'high',
    pattern: /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/,
    description: 'A shell command built with a template literal that interpolates a variable — input can break out of the command.',
    fix: 'Pass arguments as an array with execFile/spawn (no shell), or validate/escape the interpolated value against an allowlist.',
  },
  {
    id: 'exec-concat',
    name: 'Shell command with string concatenation',
    severity: 'high',
    pattern: /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"][^'"]*['"]\s*\+/,
    description: 'A shell command built by concatenating a string with a variable — input can break out of the command.',
    fix: 'Pass arguments as an array with execFile/spawn (no shell), or validate/escape the concatenated value against an allowlist.',
  },
  {
    id: 'sql-string-concat',
    name: 'SQL built from strings',
    severity: 'high',
    pattern: /\.(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/,
    description: 'A SQL query built by interpolating or concatenating a variable into the query string — classic SQL injection.',
    fix: 'Use parameterized queries / prepared statements with bound parameters instead of building SQL from strings.',
  },
  {
    id: 'inner-html',
    name: 'Unsanitized HTML assignment',
    severity: 'medium',
    pattern: /\.innerHTML\s*=(?!=)/,
    description: 'Assigning to innerHTML parses the value as HTML; with user input that is stored cross-site scripting.',
    fix: 'Use textContent for plain text, or sanitize the HTML with a library such as DOMPurify before assigning it.',
  },
  {
    id: 'document-write',
    name: 'document.write call',
    severity: 'medium',
    pattern: /document\.write\s*\(/,
    description: 'document.write parses its argument as HTML; with user input that is cross-site scripting, and it blocks parsing.',
    fix: 'Avoid document.write; build DOM nodes with textContent or a templating library instead.',
  },
  {
    id: 'dangerously-set-inner-html',
    name: 'React raw-HTML prop',
    severity: 'medium',
    pattern: new RegExp(RAW_HTML_PROP),
    description: 'The React raw-HTML prop renders its value as HTML without escaping; with user input that is cross-site scripting.',
    fix: 'Avoid the raw-HTML prop; render text normally, or sanitize the HTML with a library such as DOMPurify first.',
  },
];

const JS_TS_EXTENSIONS = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/;

export const injectionCheck: RepoCheckModule = {
  id: 'injection',
  name: 'Injection patterns',
  cleanDetail: (filesScanned: number) => `No injection patterns found in ${filesScanned} file(s).`,
  run(files: ScannedFile[], ctx: RepoCheckContext): RepoFinding[] {
    const findings: RepoFinding[] = [];
    for (const file of files) {
      if (!JS_TS_EXTENSIONS.test(file.relPath)) continue;
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const p of PATTERNS) {
          if (!p.pattern.test(line)) continue;
          if (ctx.allowlist.isAllowed(file.relPath, p.id)) continue;
          findings.push({
            id: p.id,
            name: p.name,
            status: 'fail',
            severity: p.severity,
            detail: `${p.name} (${p.id}). ${p.description}`,
            fix: p.fix,
            file: file.relPath,
            line: i + 1,
            ruleId: p.id,
          });
        }
      }
    }
    return findings;
  },
};
