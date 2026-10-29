/**
 * Value Object Anti-SSRF para URLs de destino de Webhooks.
 * Bloquea direcciones loopback, redes privadas RFC 1918 y endpoints de metadatos Cloud (169.254.169.254).
 */
export class SafeWebhookTargetVO {
  public readonly url: string;
  public readonly host: string;
  public readonly hostname: string;

  private static readonly PRIVATE_OR_LOOPBACK_PATTERNS = [
    /^localhost$/i,
    /^127\.\d+\.\d+\.\d+$/,
    /^10\.\d+\.\d+\.\d+$/,
    /^192\.168\.\d+\.\d+$/,
    /^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/,
    /^169\.254\.\d+\.\d+$/,
    /^0\.0\.0\.0$/,
    /^\[?::1\]?$/,
    /^\[?fe80:/i,
    /^\[?fc00:/i,
    /^\[?fd00:/i,
  ];

  constructor(rawUrl: string) {
    const trimmed = (rawUrl || '').trim();
    if (!trimmed) {
      throw new Error('targetUrl es obligatorio');
    }

    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new Error(`targetUrl inválido: ${trimmed}`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Protocolo de webhook no permitido. Solo se admite HTTP o HTTPS.');
    }

    const hostname = parsed.hostname.toLowerCase();
    for (const pattern of SafeWebhookTargetVO.PRIVATE_OR_LOOPBACK_PATTERNS) {
      if (pattern.test(hostname)) {
        throw new Error(
          `SSRF bloqueado: el host de destino '${hostname}' pertenece a una red privada, loopback o servicio de metadatos interno.`
        );
      }
    }

    this.url = parsed.toString();
    this.host = parsed.host;
    this.hostname = hostname;
  }
}
