import {
  WebhookDispatcherPort,
  WebhookDispatchRequest,
  WebhookDispatchResult,
} from '../../domain/ports/webhook-dispatcher.port';

/**
 * Adaptador HTTP para despacho de Webhooks con soporte dual:
 * - Despacho HTTP real mediante Node 20 fetch() + AbortSignal.timeout()
 * - Modo determinista de simulación cuando simulateTargetStatus es provisto.
 */
export class FetchWebhookDispatcherAdapter implements WebhookDispatcherPort {
  async send(request: WebhookDispatchRequest): Promise<WebhookDispatchResult> {
    if (typeof request.simulateTargetStatus === 'number') {
      return this.sendSyncOrSimulated(request);
    }

    const start = performance.now();
    try {
      const response = await fetch(request.targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-HookRelay-Event': request.eventType,
          'X-HookRelay-Idempotency-Key': request.idempotencyKey,
          'X-HookRelay-Signature-256': request.hmacHeader,
        },
        body: request.payloadJson,
        signal: AbortSignal.timeout(request.timeoutMs || 3500),
      });

      const latencyMs = Number((performance.now() - start).toFixed(2));
      const ok = response.status >= 200 && response.status < 300;
      return {
        httpStatus: response.status,
        latencyMs,
        ok,
        detail: ok
          ? `Entregado exitosamente a ${request.targetUrl} con firma ${request.hmacHeader.slice(0, 28)}...`
          : `Fallo HTTP ${response.status} desde ${request.targetUrl}`,
      };
    } catch (err: any) {
      const latencyMs = Number((performance.now() - start).toFixed(2));
      return {
        httpStatus: 504,
        latencyMs,
        ok: false,
        detail: `Error de red o timeout hacia ${request.targetUrl}: ${err?.message || 'Timeout'}`,
      };
    }
  }

  sendSyncOrSimulated(request: WebhookDispatchRequest): WebhookDispatchResult {
    const status = request.simulateTargetStatus ?? 200;
    const ok = status >= 200 && status < 300;
    return {
      httpStatus: status,
      latencyMs: ok ? 12.4 : 145.0,
      ok,
      detail: ok
        ? `Entregado exitosamente a ${request.targetUrl} con firma ${request.hmacHeader.slice(0, 28)}...`
        : `Fallo HTTP ${status} en ${request.targetUrl}`,
    };
  }
}

export const fetchWebhookDispatcher = new FetchWebhookDispatcherAdapter();
