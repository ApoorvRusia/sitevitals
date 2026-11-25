// Check-module contract. Check files in src/checks/ are grouped by area
// (dns, headers, https, tls) — one file per group, not one per check id.
// Passive checks only — no scans, no payloads.

export type CheckStatus = 'pass' | 'fail' | 'error';
export type Severity = 'low' | 'medium' | 'high';

export interface CheckResult {
  /** Same as the module's check id (e.g. 'hsts'). */
  id: string;
  /** Human-readable check name. */
  name: string;
  /** 'error' means the check couldn't run (timeout, DNS down) — it must
      never masquerade as a vulnerability. */
  status: CheckStatus;
  severity: Severity;
  /** One-line plain-English explanation of what was found. */
  detail: string;
  /** Remediation snippet shown when status is 'fail'. */
  fix?: string;
}

export interface CheckContext {
  /** Normalized target URL (https unless the target genuinely has no TLS). */
  url: URL;
  /** Hostname without port, used by DNS/TLS checks. */
  hostname: string;
  /** Port for TLS/HTTPS probes (443 unless the URL specified one). */
  port: number;
}

export interface CheckModule {
  id: string;
  run(ctx: CheckContext): Promise<CheckResult[]>;
}
