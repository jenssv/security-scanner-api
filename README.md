# Security Scanner API

An API that checks a website's **uptime** and **SSL/TLS certificate**, built with Node.js and Fastify and deployed on AWS EC2.

```
GET /scan?url=github.com
```

```json
{
  "target": "github.com",
  "scannedAt": "2026-11-17T06:00:00.000Z",
  "uptime": {
    "online": true,
    "statusCode": 200,
    "responseTimeMs": 182,
    "finalUrl": "https://github.com/",
    "redirects": []
  },
  "ssl": {
    "enabled": true,
    "valid": true,
    "protocol": "TLSv1.3",
    "issuer": "Sectigo Limited",
    "validTo": "2027-02-05T23:59:59.000Z",
    "expiresInDays": 80,
    "expiringSoon": false
  }
}
```

## What it checks

| Check | Why it matters |
|---|---|
| **Uptime**: status code, response time, redirect chain | Detects outages and slow responses |
| **SSL certificate**: validity, issuer, expiry date, TLS version | Expired or invalid certificates break sites and expose users to interception |

## Security design

A service that fetches user-supplied URLs is a classic target for **Server-Side Request Forgery (SSRF)**: an attacker asks the server to fetch internal addresses it can reach but the attacker can't, such as the AWS metadata service at `169.254.169.254`, which can leak cloud credentials. This was the root cause of the 2019 Capital One breach.

This API defends against it in [`src/lib/safe-target.js`](src/lib/safe-target.js):

- **IP blocklist at connection time.** Every DNS lookup goes through `safeLookup()`, which refuses any hostname that resolves to a private, loopback, link-local, or reserved range (IPv4 and IPv6). The check happens when the socket connects, which also blocks **DNS rebinding** attacks.
- **Redirects are re-validated.** Every redirect hop goes through the same checks, so `https://evil.example` can't redirect the scanner to `http://127.0.0.1`.
- **Only http/https on default ports.** The scanner can't be used to probe arbitrary ports.
- **No credentials in URLs** (`https://user:pass@host` is rejected).
- **Rate limiting.** 20 scans per minute per IP.

## Run locally

```bash
npm install
npm start          # http://localhost:3000
```

Set `PORT` to change the port.

## Roadmap

- [x] Uptime + SSL checks
- [x] SSRF protection and rate limiting
- [ ] Security header analysis (HSTS, CSP, X-Frame-Options…) with an A–F grade
- [ ] Detection of version-leaking headers (`Server`, `X-Powered-By`)
- [ ] Scheduled monitoring with Telegram alerts
- [ ] Serverless version: Lambda + EventBridge + DynamoDB
- [ ] Port check for domain owners, verified via DNS TXT record
