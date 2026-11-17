import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';
import { checkSsl } from './checks/ssl.js';
import { checkUptime } from './checks/uptime.js';
import { BlockedTargetError, parseTarget } from './lib/safe-target.js';

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

const app = Fastify({ logger: true });

// Max 20 scans per minute per IP, so nobody can use this API to flood
// other websites.
await app.register(rateLimit, { max: 20, timeWindow: '1 minute' });

app.get('/', async () => ({
  name: 'Security Scanner API',
  version: '0.1.0',
  endpoints: {
    scan: '/scan?url=example.com',
    health: '/health',
  },
}));

app.get('/health', async () => ({ status: 'ok' }));

app.get(
  '/scan',
  {
    schema: {
      querystring: {
        type: 'object',
        required: ['url'],
        properties: { url: { type: 'string', minLength: 1, maxLength: 2048 } },
      },
    },
  },
  async (request, reply) => {
    try {
      const target = parseTarget(request.query.url);

      const [uptime, ssl] = await Promise.all([checkUptime(target), checkSsl(target.hostname)]);
      const { headers, ...uptimeReport } = uptime;

      return {
        target: target.hostname,
        scannedAt: new Date().toISOString(),
        uptime: uptimeReport,
        ssl,
      };
    } catch (err) {
      if (err instanceof BlockedTargetError) {
        return reply.code(400).send({ error: err.message });
      }
      throw err;
    }
  },
);

try {
  await app.listen({ port: PORT, host: HOST });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
