// tls — certificate validity/chain and TLS version floor.
// Passive: opens a TLS handshake only, sends no application data.
import tls from 'node:tls';
import { CheckModule, CheckResult } from '../types.js';

function getTlsInfo(hostname: string, port: number): Promise<{ protocol: string; cert: tls.PeerCertificate }> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('TLS handshake timed out'));
    }, 20_000);

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false, // we report validity ourselves, never masquerade
        minVersion: 'TLSv1' as const,
      },
      () => {
        clearTimeout(timeout);
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol() ?? 'unknown';
        socket.end();
        resolve({ protocol, cert });
      },
    );
    socket.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

export const tlsCheck: CheckModule = {
  id: 'tls',
  async run(ctx) {
    const results: CheckResult[] = [];
    let info: { protocol: string; cert: tls.PeerCertificate };
    try {
      info = await getTlsInfo(ctx.hostname, ctx.port);
    } catch (err) {
      return [
        {
          id: 'tls-handshake',
          name: 'TLS',
          status: 'error',
          severity: 'high',
          detail: `TLS handshake failed (${(err as Error).message}).`,
        },
      ];
    }

    // Certificate validity
    const cert = info.cert;
    if (!cert || Object.keys(cert).length === 0) {
      results.push({
        id: 'tls-cert',
        name: 'Certificate validity',
        status: 'fail',
        severity: 'high',
        detail: 'Server returned no certificate.',
        fix: 'Install a valid certificate from a trusted CA (e.g. Let\'s Encrypt).',
      });
      results.push({
        id: 'cert-expiry-window',
        name: 'Certificate expiry window',
        status: 'error',
        severity: 'high',
        detail: 'No certificate returned — expiry window cannot be evaluated.',
      });
    } else {
      const validTo = new Date(cert.valid_to).getTime();
      const now = Date.now();
      const daysLeft = Math.round((validTo - now) / 86_400_000);
      const issuedTo = cert.subject?.CN ?? 'unknown';
      if (validTo <= now) {
        results.push({
          id: 'tls-cert',
          name: 'Certificate validity',
          status: 'fail',
          severity: 'high',
          detail: `Certificate for ${issuedTo} EXPIRED (${cert.valid_to}).`,
          fix: 'Renew the certificate immediately and automate renewal (certbot renew).',
        });
      } else {
        results.push({
          id: 'tls-cert',
          name: 'Certificate validity',
          status: 'pass',
          severity: 'high',
          detail: `Valid certificate for ${issuedTo}; expires in ${daysLeft} days (${cert.valid_to}).`,
        });
      }

      // Expiry window — a valid cert that dies within 30 days is an
      // imminent outage, not a clean bill of health. Separate from
      // tls-cert so a short-lived-but-valid cert still fails here.
      // An expired cert also fails here (daysLeft <= 0 < 30).
      results.push({
        id: 'cert-expiry-window',
        name: 'Certificate expiry window',
        status: daysLeft < 30 ? 'fail' : 'pass',
        severity: 'high',
        detail:
          daysLeft < 30
            ? `Certificate for ${issuedTo} expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'} (${cert.valid_to}) — inside the 30-day renewal window.`
            : `Certificate for ${issuedTo} expires in ${daysLeft} days (${cert.valid_to}) — outside the 30-day renewal window.`,
        ...(daysLeft < 30
          ? { fix: 'Renew the certificate now and automate renewal so it never gets inside 30 days (certbot renew --deploy-hook, or your CA auto-renewal).' }
          : {}),
      });
    }

    // TLS version floor
    const protocol = info.protocol; // e.g. 'TLSv1.3'
    const ok = protocol === 'TLSv1.3' || protocol === 'TLSv1.2';
    results.push({
      id: 'tls-version',
      name: 'TLS version floor',
      status: ok ? 'pass' : 'fail',
      severity: 'high',
      detail: `Negotiated ${protocol}.`,
      fix: ok ? undefined : 'Disable TLS 1.0/1.1 on the server; require TLS 1.2+.',
    });

    return results;
  },
};
