import { EndpointCircuitBreaker } from '../src/domain/state/circuit-breaker.state';
import { ExponentialFullJitterStrategy } from '../src/domain/strategy/backoff.strategy';
import { HmacSignerService } from '../src/infrastructure/crypto/hmac-signer.service';
import { WebhookRelayUseCase } from '../src/application/use-cases/webhook-relay.use-case';

describe('HookRelay API — Circuit Breaker, Exponential Backoff, HMAC-SHA256 & Dead-Letter Queue', () => {
  it('State Pattern (Circuit Breaker): transiciona de CLOSED -> OPEN tras fallos consecutivos y pasa a HALF_OPEN tras el cooldown', () => {
    const breaker = new EndpointCircuitBreaker('api.cliente-caido.com', 3, 10000);
    expect(breaker.canPass(1000).state).toBe('CLOSED');

    breaker.recordFailure(1000);
    breaker.recordFailure(2000);
    expect(breaker.canPass(2500).allowed).toBe(true);

    // 3er fallo consecutivo abre el circuito
    breaker.recordFailure(3000);
    const blocked = breaker.canPass(5000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.state).toBe('OPEN');

    // Después de los 10,000ms de cooldown transiciona a HALF_OPEN
    const halfOpen = breaker.canPass(13500);
    expect(halfOpen.allowed).toBe(true);
    expect(halfOpen.state).toBe('HALF_OPEN');

    // Al registrar éxito en HALF_OPEN vuelve a CLOSED
    breaker.recordSuccess();
    expect(breaker.snapshot().state).toBe('CLOSED');
  });

  it('Strategy Pattern (Exponential Backoff): duplica exponencialmente el tiempo de espera entre intentos', () => {
    const strategy = new ExponentialFullJitterStrategy(1000, 60000, 1.0);
    expect(strategy.computeNextDelayMs(1)).toBe(1000);
    expect(strategy.computeNextDelayMs(2)).toBe(2000);
    expect(strategy.computeNextDelayMs(3)).toBe(4000);
    expect(strategy.computeNextDelayMs(4)).toBe(8000);
  });

  it('HmacSignerService: firma payloads con HMAC-SHA256 y rechaza firmas alteradas o fuera de ventana anti-replay', () => {
    const signer = new HmacSignerService();
    const payload = JSON.stringify({ invoiceId: 'FE-901', total: 450000 });
    const secret = 'whsec_super_secret_test';
    const ts = 1760000000;

    const header = signer.signPayload(payload, secret, ts);
    expect(signer.verifySignature(payload, secret, header, 300, ts + 45).valid).toBe(true);
    expect(signer.verifySignature(payload, 'wrong_secret', header, 300, ts + 45).valid).toBe(false);
    expect(signer.verifySignature(payload, secret, header, 300, ts + 999).valid).toBe(false);
  });

  it('WebhookRelayUseCase: garantiza idempotencia, mueve fallos 5xx a la Dead-Letter Queue (DLQ) y permite Replay', () => {
    const useCase = new WebhookRelayUseCase();

    // 1. Envío exitoso e idempotente
    const first = useCase.dispatch({
      idempotencyKey: 'idem_order_777',
      eventType: 'invoice.paid',
      targetUrl: 'https://erp.empresa.co/webhooks',
      payload: { orderId: 777 },
    });
    expect(first.deduplicated).toBe(false);
    expect(first.event.status).toBe('DELIVERED');

    const duplicate = useCase.dispatch({
      idempotencyKey: 'idem_order_777',
      eventType: 'invoice.paid',
      targetUrl: 'https://erp.empresa.co/webhooks',
      payload: { orderId: 777 },
    });
    expect(duplicate.deduplicated).toBe(true);
    expect(duplicate.event.id).toBe(first.event.id);

    // 2. Destino caído (HTTP 502) -> Agota reintentos y pasa a DLQ
    const failed = useCase.dispatch({
      eventType: 'patient.rda_emitted',
      targetUrl: 'https://nodo-caido.salud.co/hook',
      maxRetries: 3,
      simulateTargetStatus: 502,
      payload: { bundleId: 'RDA-1888' },
    });
    expect(failed.event.status).toBe('DEAD_LETTER_QUEUE');
    expect(failed.event.attempts).toHaveLength(3);

    // 3. Replay manual desde DLQ cuando el servidor destino se recupera (HTTP 200)
    const replayed = useCase.replayFromDlq(failed.event.id, 200);
    expect(replayed.event.status).toBe('DELIVERED');
    expect(replayed.circuitState.state).toBe('CLOSED');
  });
});
