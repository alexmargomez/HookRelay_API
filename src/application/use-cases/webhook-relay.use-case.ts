import crypto from 'crypto';
import { WebhookDispatcherPort } from '../../domain/ports/webhook-dispatcher.port';
import { WebhookOutboxRepositoryPort } from '../../domain/ports/webhook-outbox-repository.port';
import {
  CircuitBreakerSnapshot,
  EndpointCircuitBreaker,
} from '../../domain/state/circuit-breaker.state';
import { resolveBackoffStrategy } from '../../domain/strategy/backoff.strategy';
import { SafeWebhookTargetVO } from '../../domain/value-objects/safe-webhook-target.vo';
import { HmacSignerService, hmacSignerService } from '../../infrastructure/crypto/hmac-signer.service';
import {
  FetchWebhookDispatcherAdapter,
  fetchWebhookDispatcher,
} from '../../infrastructure/http/fetch-webhook-dispatcher.adapter';
import { InMemoryOutboxRepository } from '../../infrastructure/persistence/in-memory-outbox.repository';

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
 * Orquesta el despacho confiable de Webhooks con validación Anti-SSRF (SafeWebhookTargetVO),
 * puerto de despacho HTTP (WebhookDispatcherPort) y persistencia desacoplada (WebhookOutboxRepositoryPort).
 */
export class WebhookRelayUseCase {
  private circuitBreakers = new Map<string, EndpointCircuitBreaker>();
  private readonly defaultSecret =
    process.env.HOOKRELAY_DEFAULT_SECRET || 'whsec_hookrelay_hmac_sha256_2026';

  constructor(
    private readonly signer: HmacSignerService = hmacSignerService,
    private readonly outboxRepository: WebhookOutboxRepositoryPort = new InMemoryOutboxRepository(),
    private readonly dispatcher: WebhookDispatcherPort = fetchWebhookDispatcher
  ) {}

  dispatch(input: DispatchWebhookInput): {
    deduplicated: boolean;
    event: OutboxWebhookEvent;
    circuitState: CircuitBreakerSnapshot;
  } {
    if (!input.targetUrl || !input.eventType) {
      throw new Error('targetUrl y eventType son obligatorios');
    }

    const safeTarget = new SafeWebhookTargetVO(input.targetUrl);

    const idemKey =
      (input.idempotencyKey || '').trim() || `idem_${crypto.randomBytes(8).toString('hex')}`;

    // 1. Idempotent Receiver Pattern: consultar por el puerto de salida
    const existingEv = this.outboxRepository.findByIdempotencyKey(idemKey);
    if (existingEv) {
      const breaker = this.getOrCreateBreaker(existingEv.targetHost);
      return {
        deduplicated: true,
        event: existingEv,
        circuitState: breaker.snapshot(),
      };
    }

    const targetHost = safeTarget.host;
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
      targetUrl: safeTarget.url,
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
      input.simulateTargetStatus || 200,
      payloadJson
    );

    this.outboxRepository.save(event);

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
    const event = this.outboxRepository.findById(eventId);
    if (!event) {
      throw new Error(`No existe ningún evento con ID ${eventId}`);
    }

    const breaker = this.getOrCreateBreaker(event.targetHost);
    breaker.recordSuccess();

    this.executeDeliveryCommand(
      event,
      breaker,
      'EXPONENTIAL',
      simulateTargetStatus,
      JSON.stringify(event.payload || {})
    );
    this.outboxRepository.save(event);
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
    const all = this.outboxRepository.findAllNewestFirst();
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
    simulatedStatus: number,
    payloadJson: string
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

    const result = this.dispatcher.sendSyncOrSimulated({
      targetUrl: event.targetUrl,
      eventType: event.eventType,
      idempotencyKey: event.idempotencyKey,
      hmacHeader: event.hmacHeader,
      payloadJson,
      simulateTargetStatus: simulatedStatus,
    });

    if (result.ok) {
      event.attemptsCount += 1;
      event.status = 'DELIVERED';
      breaker.recordSuccess();
      event.attempts.push({
        attemptNumber: event.attemptsCount,
        executedAt: new Date().toISOString(),
        httpStatus: result.httpStatus,
        latencyMs: result.latencyMs,
        outcome: 'DELIVERED_2XX',
        nextRetryDelayMs: null,
        detail: result.detail,
      });
      return;
    }

    for (let i = 1; i <= event.maxRetries; i++) {
      event.attemptsCount += 1;
      breaker.recordFailure();
      const isLast = i === event.maxRetries;
      const delayMs = isLast ? null : strategy.computeNextDelayMs(i);
      event.attempts.push({
        attemptNumber: event.attemptsCount,
        executedAt: new Date().toISOString(),
        httpStatus: result.httpStatus,
        latencyMs: result.latencyMs,
        outcome: 'FAILED_5XX_OR_TIMEOUT',
        nextRetryDelayMs: delayMs,
        detail: isLast
          ? `Reintentos agotados (${event.maxRetries}/${event.maxRetries}). Movido a Dead-Letter Queue (DLQ).`
          : `Fallo HTTP ${result.httpStatus}. Próximo reintento programado en ${delayMs}ms (${strategy.name}).`,
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
}

export const webhookRelayUseCase = new WebhookRelayUseCase(
  hmacSignerService,
  new InMemoryOutboxRepository(5000),
  new FetchWebhookDispatcherAdapter()
);
