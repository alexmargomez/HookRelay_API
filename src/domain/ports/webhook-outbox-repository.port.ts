import { OutboxWebhookEvent } from '../../application/use-cases/webhook-relay.use-case';

/**
 * Outbound Port (Hexagonal Architecture) —
 * Define el contrato de persistencia para eventos del Transactional Outbox,
 * índice de idempotencia y Dead-Letter Queue (DLQ).
 */
export interface WebhookOutboxRepositoryPort {
  save(event: OutboxWebhookEvent): void;
  findById(eventId: string): OutboxWebhookEvent | undefined;
  findByIdempotencyKey(idempotencyKey: string): OutboxWebhookEvent | undefined;
  findAllNewestFirst(): OutboxWebhookEvent[];
  count(): number;
}
