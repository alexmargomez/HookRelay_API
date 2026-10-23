import Fastify from 'fastify';
import cors from '@fastify/cors';
import {
  DispatchWebhookInput,
  webhookRelayUseCase,
} from './application/use-cases/webhook-relay.use-case';
import { hmacSignerService } from './infrastructure/crypto/hmac-signer.service';

export function buildServer() {
  const app = Fastify({ logger: false });
  app.register(cors, { origin: true });

  app.get('/', async (_req, reply) => {
    reply.type('text/html; charset=utf-8').send(`<!doctype html>
<html>
  <head>
    <title>HookRelay API — Reliable Webhook Gateway (HMAC + Circuit Breaker + DLQ)</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="/api/v1/openapi.json" data-configuration='{"theme":"mars","darkMode":true}'></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`);
  });

  app.get('/docs', async (_req, reply) => {
    reply.redirect('/');
  });

  app.get('/api/v1/openapi.json', async () => ({
    openapi: '3.1.0',
    info: {
      title:
        'HookRelay API — Gateway de Webhooks Confiables con Firma HMAC-SHA256, Circuit Breaker y Dead-Letter Queue',
      version: '1.0.0',
      description:
        'Microservicio 100% Backend en Node.js 20 + TypeScript + Fastify bajo Event-Driven Outbox y Arquitectura Hexagonal.',
    },
    paths: {
      '/api/v1/health': {
        get: {
          summary: 'Estado del Gateway y resumen de Circuit Breakers / DLQ',
          tags: ['1. Telemetría & Estado'],
        },
      },
      '/api/v1/webhooks/dispatch': {
        post: {
          summary:
            'Despachar un Webhook firmado con HMAC-SHA256, Idempotency-Key y política Exponential Backoff + Jitter',
          tags: ['2. Despacho & Outbox'],
        },
      },
      '/api/v1/webhooks/deliveries': {
        get: {
          summary: 'Consultar historial de entregas, intentos, estados de Circuit Breaker y Dead-Letter Queue',
          tags: ['2. Despacho & Outbox'],
        },
      },
      '/api/v1/webhooks/dlq/{id}/replay': {
        post: {
          summary: 'Re-ejecutar (Replay Command) un evento fallido desde la Dead-Letter Queue (DLQ)',
          tags: ['3. Dead-Letter Queue (DLQ) & Verificación HMAC'],
        },
      },
      '/api/v1/webhooks/verify-signature': {
        post: {
          summary: 'Verificar autenticidad criptográfica de una cabecera X-HookRelay-Signature-256 (timingSafeEqual)',
          tags: ['3. Dead-Letter Queue (DLQ) & Verificación HMAC'],
        },
      },
    },
  }));

  app.get('/api/v1/health', async () => {
    const summary = webhookRelayUseCase.listDeliveries();
    return {
      status: 'UP',
      service: 'HookRelay API (Node.js 20 + TypeScript 5 + Fastify)',
      architecture: 'Event-Driven Outbox + Hexagonal (State + Strategy + Command + Idempotent Receiver)',
      totalEvents: summary.totalEvents,
      deliveredCount: summary.deliveredCount,
      dlqCount: summary.dlqCount,
      activeCircuitBreakers: summary.circuitBreakers,
      timestamp: new Date().toISOString(),
    };
  });

  app.post('/api/v1/webhooks/dispatch', async (req, reply) => {
    try {
      const body = (req.body || {}) as DispatchWebhookInput;
      const res = webhookRelayUseCase.dispatch(body);
      return reply.code(res.deduplicated ? 200 : 202).send(res);
    } catch (err: any) {
      return reply.code(400).send({ error: err.message });
    }
  });

  app.get('/api/v1/webhooks/deliveries', async () => {
    return webhookRelayUseCase.listDeliveries();
  });

  app.post('/api/v1/webhooks/dlq/:id/replay', async (req, reply) => {
    try {
      const { id } = req.params as { id: string };
      const body = (req.body || {}) as { simulateTargetStatus?: number };
      return webhookRelayUseCase.replayFromDlq(id, body.simulateTargetStatus || 200);
    } catch (err: any) {
      return reply.code(404).send({ error: err.message });
    }
  });

  app.post('/api/v1/webhooks/verify-signature', async (req) => {
    const body = (req.body || {}) as {
      payloadJson: string;
      secret: string;
      signatureHeader: string;
    };
    return hmacSignerService.verifySignature(
      body.payloadJson || '{}',
      body.secret || 'whsec_hookrelay_hmac_sha256_2026',
      body.signatureHeader || ''
    );
  });

  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT || process.env.BACKEND_PORT || 8088);
  const server = buildServer();
  server.listen({ host: '0.0.0.0', port }, (err, address) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`🔔 HookRelay API escuchando en ${address}`);
  });
}
