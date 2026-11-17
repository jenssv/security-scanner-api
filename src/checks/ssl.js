// SSL/TLS check: is the certificate valid, who issued it, and when does it
// expire?

import { isIP } from 'node:net';
import tls from 'node:tls';
import { assertSafeHost, BlockedTargetError, safeLookup } from '../lib/safe-target.js';

const EXPIRY_WARNING_DAYS = 30;

export function checkSsl(hostname, { timeoutMs = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    try {
      assertSafeHost(hostname);
    } catch (err) {
      return reject(err);
    }
    hostname = hostname.replace(/^\[|\]$/g, '');

    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: isIP(hostname) ? undefined : hostname, // SNI
      lookup: safeLookup,
      // Connect even when the certificate is bad, so we can report what is wrong.
      rejectUnauthorized: false,
    });

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish(resolve, { enabled: false, error: 'Timed out connecting on port 443' });
    });

    socket.on('error', (err) => {
      if (err instanceof BlockedTargetError) return finish(reject, err);
      finish(resolve, { enabled: false, error: err.code || err.message });
    });

    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      socket.end();

      if (!cert || Object.keys(cert).length === 0) {
        return finish(resolve, { enabled: true, valid: false, error: 'No certificate presented', protocol });
      }

      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const expiresInDays = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);

      finish(resolve, {
        enabled: true,
        valid: authorized,
        error: authError ? String(authError) : null,
        protocol,
        subject: cert.subject?.CN ?? null,
        issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
        validFrom: validFrom.toISOString(),
        validTo: validTo.toISOString(),
        expiresInDays,
        expiringSoon: expiresInDays >= 0 && expiresInDays < EXPIRY_WARNING_DAYS,
        coveredNames: cert.subjectaltname
          ? cert.subjectaltname.split(', ').map((s) => s.replace(/^(DNS|IP Address):/, ''))
          : [],
      });
    });
  });
}
