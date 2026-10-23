/**
 * State Pattern — Máquina de Estados Finita para el Cortacircuitos (Circuit Breaker)
 * por dominio/endpoint destino: CLOSED -> OPEN -> HALF_OPEN -> CLOSED.
 */
export type CircuitStateName = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerSnapshot {
  targetHost: string;
  state: CircuitStateName;
  consecutiveFailures: number;
  failureThreshold: number;
  cooldownMs: number;
  openedAtMs: number | null;
  remainingCooldownMs: number;
}

export class EndpointCircuitBreaker {
  private state: CircuitStateName = 'CLOSED';
  private consecutiveFailures = 0;
  private openedAtMs: number | null = null;

  constructor(
    public readonly targetHost: string,
    public readonly failureThreshold = 3,
    public readonly cooldownMs = 30000
  ) {}

  canPass(nowMs = Date.now()): { allowed: boolean; state: CircuitStateName; reason?: string } {
    if (this.state === 'CLOSED') {
      return { allowed: true, state: 'CLOSED' };
    }

    if (this.state === 'OPEN') {
      const elapsed = this.openedAtMs ? nowMs - this.openedAtMs : this.cooldownMs;
      if (elapsed >= this.cooldownMs) {
        this.state = 'HALF_OPEN';
        return { allowed: true, state: 'HALF_OPEN' };
      }
      const remSec = Math.ceil((this.cooldownMs - elapsed) / 1000);
      return {
        allowed: false,
        state: 'OPEN',
        reason: `Circuit Breaker OPEN para ${this.targetHost} (enfriamiento restante: ${remSec}s)`,
      };
    }

    // En HALF_OPEN se permite pasar 1 intento de prueba
    return { allowed: true, state: 'HALF_OPEN' };
  }

  recordSuccess(): void {
    this.consecutiveFailures = 0;
    this.state = 'CLOSED';
    this.openedAtMs = null;
  }

  recordFailure(nowMs = Date.now()): void {
    this.consecutiveFailures += 1;
    if (this.state === 'HALF_OPEN' || this.consecutiveFailures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.openedAtMs = nowMs;
    }
  }

  snapshot(nowMs = Date.now()): CircuitBreakerSnapshot {
    // Actualizar transición automática si el cooldown ya expiró
    if (this.state === 'OPEN' && this.openedAtMs && nowMs - this.openedAtMs >= this.cooldownMs) {
      this.state = 'HALF_OPEN';
    }
    const remaining =
      this.state === 'OPEN' && this.openedAtMs
        ? Math.max(0, this.cooldownMs - (nowMs - this.openedAtMs))
        : 0;

    return {
      targetHost: this.targetHost,
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      failureThreshold: this.failureThreshold,
      cooldownMs: this.cooldownMs,
      openedAtMs: this.openedAtMs,
      remainingCooldownMs: remaining,
    };
  }
}
