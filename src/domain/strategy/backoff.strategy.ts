/**
 * Strategy Pattern — Políticas intercambiables de tiempo de espera entre reintentos
 * (Exponential Backoff con Full Jitter, Lineal y Fijo).
 */
export interface RetryBackoffStrategy {
  readonly name: string;
  computeNextDelayMs(attemptNumber: number): number;
}

export class ExponentialFullJitterStrategy implements RetryBackoffStrategy {
  readonly name = 'EXPONENTIAL_FULL_JITTER';

  constructor(
    private readonly baseDelayMs = 2000,
    private readonly maxDelayMs = 300000,
    private readonly deterministicJitterRatio?: number
  ) {}

  computeNextDelayMs(attemptNumber: number): number {
    const safeAttempt = Math.max(1, Math.min(10, attemptNumber));
    const exponentialCap = Math.min(this.maxDelayMs, this.baseDelayMs * Math.pow(2, safeAttempt - 1));
    const jitterFactor =
      this.deterministicJitterRatio !== undefined
        ? this.deterministicJitterRatio
        : 0.5 + Math.random() * 0.5;
    return Math.round(exponentialCap * jitterFactor);
  }
}

export class LinearBackoffStrategy implements RetryBackoffStrategy {
  readonly name = 'LINEAR_BACKOFF';

  constructor(private readonly stepDelayMs = 5000) {}

  computeNextDelayMs(attemptNumber: number): number {
    return Math.max(1, attemptNumber) * this.stepDelayMs;
  }
}

export function resolveBackoffStrategy(mode?: string): RetryBackoffStrategy {
  if ((mode || '').toUpperCase() === 'LINEAR') {
    return new LinearBackoffStrategy();
  }
  return new ExponentialFullJitterStrategy();
}
