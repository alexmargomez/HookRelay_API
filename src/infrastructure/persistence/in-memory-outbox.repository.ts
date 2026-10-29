import { OutboxWebhookEvent } from '../../application/use-cases/webhook-relay.use-case';
import { WebhookOutboxRepositoryPort } from '../../domain/ports/webhook-outbox-repository.port';

/**
 * Adaptador de Persistencia con Evicción Inteligente Priorizada —
 * Implementa WebhookOutboxRepositoryPort protegiendo el heap de Node.js
 * y priorizando la preservación de eventos en DEAD_LETTER_QUEUE frente a eventos ya entregados.
 */
export class InMemoryOutboxRepository implements WebhookOutboxRepositoryPort {
  private readonly events = new Map<string, OutboxWebhookEvent>();
  private readonly idempotencyIndex = new Map<string, string>();

  constructor(private readonly maxCapacity: number = 5000) {}

  save(event: OutboxWebhookEvent): void {
    if (!this.events.has(event.id) && this.events.size >= this.maxCapacity) {
      let victimKey: string | undefined;
      for (const [k, ev] of this.events.entries()) {
        if (ev.status === 'DELIVERED') {
          victimKey = k;
          break;
        }
      }
      if (!victimKey) {
        victimKey = this.events.keys().next().value;
      }
      if (victimKey) {
        const victimEvent = this.events.get(victimKey);
        if (victimEvent) {
          this.idempotencyIndex.delete(victimEvent.idempotencyKey);
        }
        this.events.delete(victimKey);
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
