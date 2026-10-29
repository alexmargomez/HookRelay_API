/**
 * Value Object Anti-SSRF para URLs de destino de Webhooks.
 * Bloquea direcciones loopback, redes privadas RFC 1918, endpoints de metadatos Cloud (169.254.169.254),
 * representaciones IPv4-mapped IPv6 en hexadecimal (ej. [::ffff:7f00:1], [::ffff:a9fe:a9fe]) y dominios de DNS Rebinding.
 */
export class SafeWebhookTargetVO {
  public readonly url: string;
  public readonly host: string;
  public readonly hostname: string;

  private static readonly PRIVATE_OR_LOOPBACK_PATTERNS = [
    /^localhost$/i,
    /\.localhost$/i,
    /\.local$/i,
    /\.internal$/i,
    /(^|\.)(localtest\.me|lvh\.me|nip\.io|sslip\.io|xip\.io)$/i,
    /^\d+$/, // IP en entero decimal puro (ej. 2130706433)
    /(^|\.)0x[0-9a-f]+/i, // IP o segmento en hexadecimal (ej. 0x7f000001 o 0x7f.0.0.1)
    /(^|\.)0\d+\./, // Notación octal (ej. 0177.0.0.1)
    /^127\.\d+\.\d+\.\d+$/,
    /^10\.\d+\.\d+\.\d+$/,
    /^192\.168\.\d+\.\d+$/,
    /^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/,
    /^169\.254\.\d+\.\d+$/,
    /^0\.0\.0\.0$/,
    /^\[?::1\]?$/,
    /^\[?::\]?$/,
    /^\[?fe80:/i,
    /^\[?fc00:/i,
    /^\[?fd[0-9a-f]{2}:/i,
    // IPv4-mapped IPv6 en formato punteado o hexadecimal normalizado por Node URL parser
    /^\[?(?:0*:)*ffff:(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[0-1])\.|0\.)/i,
    /^\[?(?:0*:)*ffff:(?:7f[0-9a-f]{2}:|0?a[0-9a-f]{2}:|c0a8:|a9fe:|ac1[0-9a-f]:|0+:)/i,
  ];

  public static isBlockedAddressOrHost(rawHostOrIp: string): boolean {
    const clean = (rawHostOrIp || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
    if (!clean) return true;
    for (const pattern of SafeWebhookTargetVO.PRIVATE_OR_LOOPBACK_PATTERNS) {
      if (pattern.test(clean) || pattern.test(`[${clean}]`)) {
        return true;
      }
    }
    return false;
  }

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
    if (SafeWebhookTargetVO.isBlockedAddressOrHost(hostname)) {
      throw new Error(
        `SSRF bloqueado: el host de destino '${hostname}' pertenece a una red privada, loopback o servicio de metadatos interno.`
      );
    }

    this.url = parsed.toString();
    this.host = parsed.host;
    this.hostname = hostname;
  }
}
