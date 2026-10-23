import crypto from 'crypto';
import {
  CircuitBreakerSnapshot,
  EndpointCircuitBreaker,
} from '../../domain/state/circuit-breaker.state';
import { resolveBackoffStrategy } from '../../domain/strategy/backoff.strategy';
import { HmacSignerService, hmacSignerService } from '../../infrastructure/crypto/hmac-signer.service';

export interface DeliveryAttemptLog {
  attemptNumber: number;
  executedAt: string;
  httpStatus: number;
  latencyMs: number;
  outcome: 'DELIVERED_2XX' | 'FAILED_5XX_OR_TIMEOUT' | 'REJECTED_BY_CIRCUIT_BREAKER';
  nextRetryDelayMs: number | null;
  detail: string;
}

export interface OutboxWebhookEvent {
  id: string;
  idempotencyKey: string;
  eventType: string;
  targetUrl: string;
  targetHost: string;
  payload: Record<string, any>;
  hmacHeader: string;
  status: 'DELIVERED' | 'RETRY_SCHEDULED' | 'DEAD_LETTER_QUEUE';
  maxRetries: number;
  attemptsCount: number;
  createdAt: string;
  attempts: DeliveryAttemptLog[];
}

export interface DispatchWebhookInput {
  idempotencyKey?: string;
  eventType: string;
  targetUrl: string;
  secret?: string;
  maxRetries?: number;
  backoffStrategy?: 'EXPONENTIAL' | 'LINEAR';
  simulateTargetStatus?: number;
  payload: Record<string, any>;
}

/**
 * Use Case + Command Pattern + Idempotent Receiver + Dead-Letter Queue (DLQ) —
 * Orquesta el despacho confiable de Webhooks con firma HMAC-SHA256, Circuit Breaker por host
 * y reintentos con Exponential Backoff + Jitter.
 */
export class WebhookRelayUseCase {
  private events = new Map<string, OutboxWebhookEvent>();
  private idempotencyIndex = new Map<string, string>();
  private circuitBreakers = new Map<string, EndpointCircuitBreaker>();
  private readonly defaultSecret =
    process.env.HOOKRELAY_DEFAULT_SECRET || 'whsec_hookrelay_hmac_sha256_2026';

  constructor(private readonly signer: HmacSignerService = hmacSignerService) {}

  dispatch(input: DispatchWebhookInput): {
    deduplicated: boolean;
    event: OutboxWebhookEvent;
    circuitState: CircuitBreakerSnapshot;
  } {
    if (!input.targetUrl || !input.eventType) {
      throw new Error('targetUrl y eventType son obligatorios');
    }

    const idemKey =
      (input.idempotencyKey || '').trim() || `idem_${crypto.randomBytes(8).toString('hex')}`;

    // 1. Idempotent Receiver Pattern: evitar despachos duplicados
    const existingId = this.idempotencyIndex.get(idemKey);
    if (existingId && this.events.has(existingId)) {
      const existingEv = this.events.get(existingId)!;
      const breaker = this.getOrCreateBreaker(existingEv.targetHost);
      return {
        deduplicated: true,
        event: existingEv,
        circuitState: breaker.snapshot(),
      };
    }

    const targetHost = this.extractHost(input.targetUrl);
    const breaker = this.getOrCreateBreaker(targetHost);
    const secret = (input.secret || '').trim() || this.defaultSecret;
    const payloadJson = JSON.stringify(input.payload || {});
    const nowSec = Math.floor(Date.now() / 1000);
    const hmacHeader = this.signer.signPayload(payloadJson, secret, nowSec);

    const id = `wh_${crypto.randomBytes(6).toString('hex')}`;
    const maxRetries = Math.min(8, Math.max(1, Number(input.maxRetries) || 3));

    const event: OutboxWebhookEvent = {
      id,
      idempotencyKey: idemKey,
      eventType: input.eventType,
      targetUrl: input.targetUrl,
      targetHost,
      payload: input.payload || {},
      hmacHeader,
      status: 'RETRY_SCHEDULED',
      maxRetries,
      attemptsCount: 0,
      createdAt: new Date().toISOString(),
      attempts: [],
    };

    this.executeDeliveryCommand(
      event,
      breaker,
      input.backoffStrategy,
      input.simulateTargetStatus || 200
    );

    this.events.set(id, event);
    this.idempotencyIndex.set(idemKey, id);

    return {
      deduplicated: false,
      event,
      circuitState: breaker.snapshot(),
    };
  }

  replayFromDlq(
    eventId: string,
    simulateTargetStatus = 200
  ): {
    replayed: boolean;
    event: OutboxWebhookEvent;
    circuitState: CircuitBreakerSnapshot;
  } {
    const event = this.events.get(eventId);
    if (!event) {
      throw new Error(`No existe ningún evento con ID ${eventId}`);
    }

    const breaker = this.getOrCreateBreaker(event.targetHost);
    // En replay manual restablecemos el circuito a HALF_OPEN si estaba OPEN
    breaker.recordSuccess();

    this.executeDeliveryCommand(event, breaker, 'EXPONENTIAL', simulateTargetStatus);
    return {
      replayed: true,
      event,
      circuitState: breaker.snapshot(),
    };
  }

  listDeliveries(): {
    totalEvents: number;
    deliveredCount: number;
    dlqCount: number;
    circuitBreakers: CircuitBreakerSnapshot[];
    events: OutboxWebhookEvent[];
  } {
    const all = Array.from(this.events.values()).reverse();
    const breakers = Array.from(this.circuitBreakers.values()).map((b) => b.snapshot());
    return {
      totalEvents: all.length,
      deliveredCount: all.filter((e) => e.status === 'DELIVERED').length,
      dlqCount: all.filter((e) => e.status === 'DEAD_LETTER_QUEUE').length,
      circuitBreakers: breakers,
      events: all,
    };
  }

  private executeDeliveryCommand(
    event: OutboxWebhookEvent,
    breaker: EndpointCircuitBreaker,
    strategyMode: string | undefined,
    simulatedStatus: number
  ): void {
    const strategy = resolveBackoffStrategy(strategyMode);
    const gate = breaker.canPass();

    if (!gate.allowed) {
      event.attemptsCount += 1;
      event.status = 'DEAD_LETTER_QUEUE';
      event.attempts.push({
        attemptNumber: event.attemptsCount,
        executedAt: new Date().toISOString(),
        httpStatus: 503,
        latencyMs: 0.1,
        outcome: 'REJECTED_BY_CIRCUIT_BREAKER',
        nextRetryDelayMs: breaker.cooldownMs,
        detail: gate.reason || 'Circuito abierto',
      });
      return;
    }

    if (simulatedStatus >= 200 && simulatedStatus < 300) {
      event.attemptsCount += 1;
      event.status = 'DELIVERED';
      breaker.recordSuccess();
      event.attempts.push({
        attemptNumber: event.attemptsCount,
        executedAt: new Date().toISOString(),
        httpStatus: simulatedStatus,
        latencyMs: 12.4,
        outcome: 'DELIVERED_2XX',
        nextRetryDelayMs: null,
        detail: `Entregado exitosamente a ${event.targetUrl} con firma ${event.hmacHeader.slice(0, 28)}...`,
      });
      return;
    }

    // Simular cadena de reintentos con Exponential Backoff + Jitter hasta agotar maxRetries
    for (let i = 1; i <= event.maxRetries; i++) {
      event.attemptsCount += 1;
      breaker.recordFailure();
      const isLast = i === event.maxRetries;
      const delayMs = isLast ? null : strategy.computeNextDelayMs(i);
      event.attempts.push({
        attemptNumber: event.attemptsCount,
        executedAt: new Date().toISOString(),
        httpStatus: simulatedStatus,
        latencyMs: 145.0,
        outcome: 'FAILED_5XX_OR_TIMEOUT',
        nextRetryDelayMs: delayMs,
        detail: isLast
          ? `Reintentos agotados (${event.maxRetries}/${event.maxRetries}). Movido a Dead-Letter Queue (DLQ).`
          : `Fallo HTTP ${simulatedStatus}. Próximo reintento programado en ${delayMs}ms (${strategy.name}).`,
      });
    }
    event.status = 'DEAD_LETTER_QUEUE';
  }

  private getOrCreateBreaker(host: string): EndpointCircuitBreaker {
    let b = this.circuitBreakers.get(host);
    if (!b) {
      b = new EndpointCircuitBreaker(host, 3, 30000);
      this.circuitBreakers.set(host, b);
    }
    return b;
  }

  private extractHost(rawUrl: string): string {
    try {
      return new URL(rawUrl).host;
    } catch {
      return rawUrl.replace(/^https?:\/\//, '').split('/')[0] || 'unknown-host';
    }
  }
}

export const webhookRelayUseCase = new WebhookRelayUseCase();
