export interface WebhookDispatchRequest {
  targetUrl: string;
  eventType: string;
  idempotencyKey: string;
  hmacHeader: string;
  payloadJson: string;
  timeoutMs?: number;
  simulateTargetStatus?: number;
}

export interface WebhookDispatchResult {
  httpStatus: number;
  latencyMs: number;
  ok: boolean;
  detail: string;
}

export interface WebhookDispatcherPort {
  send(request: WebhookDispatchRequest): Promise<WebhookDispatchResult>;
  sendSyncOrSimulated(request: WebhookDispatchRequest): WebhookDispatchResult;
}
