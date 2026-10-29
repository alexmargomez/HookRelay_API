import { OutboxWebhookEvent } from '../../application/use-cases/webhook-relay.use-case';
import { WebhookOutboxRepositoryPort } from '../../domain/ports/webhook-outbox-repository.port';

/**
 * Adaptador de Persistencia con Evicción LRU Acotada —
 * Implementa WebhookOutboxRepositoryPort protegiendo el heap de Node.js
 * contra fugas de memoria ante millones de eventos.
 */
export class InMemoryOutboxRepository implements WebhookOutboxRepositoryPort {
  private readonly events = new Map<string, OutboxWebhookEvent>();
  private readonly idempotencyIndex = new Map<string, string>();

  constructor(private readonly maxCapacity: number = 5000) {}

  save(event: OutboxWebhookEvent): void {
    if (!this.events.has(event.id) && this.events.size >= this.maxCapacity) {
      const oldestKey = this.events.keys().next().value;
      if (oldestKey) {
        const oldestEvent = this.events.get(oldestKey);
        if (oldestEvent) {
          this.idempotencyIndex.delete(oldestEvent.idempotencyKey);
        }
        this.events.delete(oldestKey);
      }
    }
    this.events.set(event.id, event);
    this.idempotencyIndex.set(event.idempotencyKey, event.id);
  }

  findById(eventId: string): OutboxWebhookEvent | undefined {
    return this.events.get(eventId);
  }

  findByIdempotencyKey(idempotencyKey: string): OutboxWebhookEvent | undefined {
    const id = this.idempotencyIndex.get(idempotencyKey);
    if (!id) {
      return undefined;
    }
    return this.events.get(id);
  }

  findAllNewestFirst(): OutboxWebhookEvent[] {
    return Array.from(this.events.values()).reverse();
  }

  count(): number {
    return this.events.size;
  }
}
