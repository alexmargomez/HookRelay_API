import dns from 'dns';
import net from 'net';
import {
  WebhookDispatcherPort,
  WebhookDispatchRequest,
  WebhookDispatchResult,
} from '../../domain/ports/webhook-dispatcher.port';
import { SafeWebhookTargetVO } from '../../domain/value-objects/safe-webhook-target.vo';

/**
 * Adaptador HTTP para despacho de Webhooks con soporte dual:
 * - Despacho HTTP real mediante Node 20 fetch() + AbortSignal.timeout() + verificación DNS Anti-Rebinding.
 * - Modo determinista de simulación cuando simulateTargetStatus es provisto.
 */
export class FetchWebhookDispatcherAdapter implements WebhookDispatcherPort {
  constructor(
    private readonly dnsLookupFn: (
      hostname: string
    ) => Promise<Array<{ address: string; family: number }>> = (hostname) =>
      dns.promises.lookup(hostname, { all: true })
  ) {}

  async send(request: WebhookDispatchRequest): Promise<WebhookDispatchResult> {
    if (typeof request.simulateTargetStatus === 'number') {
      return this.sendSyncOrSimulated(request);
    }

    const start = performance.now();
    try {
      const safeTarget = new SafeWebhookTargetVO(request.targetUrl);
      const cleanHost = safeTarget.hostname.replace(/^\[|\]$/g, '');

      // Prevención de DNS Rebinding: resolver las IPs del dominio y verificar que ninguna sea privada/loopback
      if (net.isIP(cleanHost) === 0) {
        const resolvedRecords = await this.dnsLookupFn(cleanHost);
        if (!resolvedRecords || resolvedRecords.length === 0) {
          throw new Error(`No se pudo resolver DNS para ${cleanHost}`);
        }
        for (const rec of resolvedRecords) {
          if (SafeWebhookTargetVO.isBlockedAddressOrHost(rec.address)) {
            throw new Error(
              `SSRF / DNS Rebinding bloqueado: '${cleanHost}' resolvió a la IP interna prohibida '${rec.address}'`
            );
          }
        }
      }

      const response = await fetch(safeTarget.url, {
        method: 'POST',
        redirect: 'error',
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
        detail: `Error de red o bloqueo de seguridad hacia ${request.targetUrl}: ${err?.message || 'Timeout'}`,
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
