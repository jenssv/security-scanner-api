// Uptime check: is the site online, how fast does it answer, and where do
// its redirects lead?

import http from 'node:http';
import https from 'node:https';
import { assertSafeUrl, BlockedTargetError, safeLookup } from '../lib/safe-target.js';

const USER_AGENT = 'SecurityScannerAPI/0.1 (+https://github.com/)';
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

function requestOnce(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, {
      method: 'GET',
      lookup: safeLookup,
      agent: false,
      // Certificate problems are reported by the SSL check, so the uptime
      // check still measures sites with bad certificates.
      rejectUnauthorized: false,
      headers: { 'user-agent': USER_AGENT, accept: '*/*' },
    });

    req.setTimeout(timeoutMs, () => req.destroy(Object.assign(new Error('Timed out'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    req.on('response', (res) => {
      // Only the status line and headers are needed; skip the body.
      resolve({ statusCode: res.statusCode, headers: res.headers });
      res.destroy();
    });
    req.end();
  });
}

export async function checkUptime(target, { timeoutMs = 8000, maxRedirects = 5 } = {}) {
  const start = performance.now();
  const redirects = [];
  let current = target;

  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const res = await requestOnce(current, timeoutMs);

      if (REDIRECT_CODES.has(res.statusCode) && res.headers.location) {
        const next = new URL(res.headers.location, current);
        assertSafeUrl(next);
        redirects.push({ from: current.href, to: next.href, statusCode: res.statusCode });
        current = next;
        continue;
      }

      return {
        online: res.statusCode < 500,
        statusCode: res.statusCode,
        responseTimeMs: Math.round(performance.now() - start),
        finalUrl: current.href,
        redirects,
        // Not returned by the API yet; Week 2's header analysis will use it.
        headers: res.headers,
      };
    }
    return { online: false, error: `More than ${maxRedirects} redirects`, redirects };
  } catch (err) {
    if (err instanceof BlockedTargetError) throw err;
    return {
      online: false,
      error: err.code || err.message,
      responseTimeMs: Math.round(performance.now() - start),
      redirects,
    };
  }
}
