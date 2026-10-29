import { FastifyInstance } from 'fastify';
import {
  DispatchWebhookInput,
  WebhookRelayUseCase,
  webhookRelayUseCase,
} from '../../../application/use-cases/webhook-relay.use-case';
import { HmacSignerService, hmacSignerService } from '../../crypto/hmac-signer.service';

export class WebhookHttpController {
  constructor(
    private readonly relayUseCase: WebhookRelayUseCase = webhookRelayUseCase,
    private readonly signer: HmacSignerService = hmacSignerService
  ) {}

  registerRoutes(app: FastifyInstance): void {
    app.get('/api/v1/health', async () => {
      const summary = this.relayUseCase.listDeliveries();
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
        const res = this.relayUseCase.dispatch(body);
        return reply.code(res.deduplicated ? 200 : 202).send(res);
      } catch (err: any) {
        return reply.code(400).send({ error: err.message });
      }
    });

    app.get('/api/v1/webhooks/deliveries', async () => {
      return this.relayUseCase.listDeliveries();
    });

    app.post('/api/v1/webhooks/dlq/:id/replay', async (req, reply) => {
      try {
        const { id } = req.params as { id: string };
        const body = (req.body || {}) as { simulateTargetStatus?: number };
        return this.relayUseCase.replayFromDlq(id, body.simulateTargetStatus || 200);
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
      return this.signer.verifySignature(
        body.payloadJson || '{}',
        body.secret || 'whsec_hookrelay_hmac_sha256_2026',
        body.signatureHeader || ''
      );
    });
  }
}
