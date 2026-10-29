import { EndpointCircuitBreaker } from '../src/domain/state/circuit-breaker.state';
import { ExponentialFullJitterStrategy } from '../src/domain/strategy/backoff.strategy';
import { SafeWebhookTargetVO } from '../src/domain/value-objects/safe-webhook-target.vo';
import { HmacSignerService } from '../src/infrastructure/crypto/hmac-signer.service';
import { WebhookRelayUseCase } from '../src/application/use-cases/webhook-relay.use-case';
import { InMemoryOutboxRepository } from '../src/infrastructure/persistence/in-memory-outbox.repository';

describe('HookRelay API — Circuit Breaker, Exponential Backoff, HMAC-SHA256 & Dead-Letter Queue', () => {
  it('State Pattern (Circuit Breaker): transiciona de CLOSED -> OPEN -> HALF_OPEN y bloquea Thundering Herd durante la sonda', () => {
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

    // Después de los 10,000ms de cooldown transiciona a HALF_OPEN y permite 1 sola sonda
    const halfOpenProbe = breaker.canPass(13500);
    expect(halfOpenProbe.allowed).toBe(true);
    expect(halfOpenProbe.state).toBe('HALF_OPEN');

    // Una segunda petición concurrente mientras la sonda sigue en vuelo debe ser rechazada (Thundering Herd Protection)
    const concurrentDuringProbe = breaker.canPass(13501);
    expect(concurrentDuringProbe.allowed).toBe(false);
    expect(concurrentDuringProbe.state).toBe('HALF_OPEN');

    // Al registrar éxito en HALF_OPEN vuelve a CLOSED y libera el candado
    breaker.recordSuccess();
    expect(breaker.snapshot().state).toBe('CLOSED');
    expect(breaker.canPass(13600).allowed).toBe(true);
  });

  it('SafeWebhookTargetVO: bloquea ataques SSRF hacia localhost, redes RFC 1918 y metadatos Cloud 169.254.169.254', () => {
    expect(new SafeWebhookTargetVO('https://erp.empresa.co/webhooks').host).toBe('erp.empresa.co');
    expect(() => new SafeWebhookTargetVO('http://127.0.0.1:3306/internal')).toThrow(/SSRF bloqueado/);
    expect(() => new SafeWebhookTargetVO('http://localhost:8080/admin')).toThrow(/SSRF bloqueado/);
    expect(() => new SafeWebhookTargetVO('http://169.254.169.254/latest/meta-data/')).toThrow(/SSRF bloqueado/);
    expect(() => new SafeWebhookTargetVO('http://192.168.1.50/router')).toThrow(/SSRF bloqueado/);
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

  it('InMemoryOutboxRepository: respeta maxCapacity y preserva eventos DLQ desalojando primero los DELIVERED', () => {
    const repo = new InMemoryOutboxRepository(2);
    const useCase = new WebhookRelayUseCase(undefined, repo);

    const dlqEv = useCase.dispatch({
      idempotencyKey: 'key_dlq',
      eventType: 'ev.dlq',
      targetUrl: 'https://caido.co/hook',
      simulateTargetStatus: 503,
      payload: {},
    });
    const deliveredEv = useCase.dispatch({
      idempotencyKey: 'key_ok_1',
      eventType: 'ev.ok1',
      targetUrl: 'https://a.co/hook',
      payload: {},
    });
    useCase.dispatch({
      idempotencyKey: 'key_ok_2',
      eventType: 'ev.ok2',
      targetUrl: 'https://a.co/hook',
      payload: {},
    });

    expect(repo.count()).toBe(2);
    // El evento en DLQ debe haberse preservado y el evento DELIVERED más antiguo desalojado
    expect(repo.findById(dlqEv.event.id)).toBeDefined();
    expect(repo.findById(deliveredEv.event.id)).toBeUndefined();
  });
});
