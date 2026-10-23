import crypto from 'crypto';

/**
 * Servicio criptográfico para firma y verificación de autenticidad de Webhooks
 * usando HMAC-SHA256 y comparación en tiempo constante (timingSafeEqual) contra Timing Attacks.
 */
export class HmacSignerService {
  signPayload(payloadJson: string, secret: string, timestampSec: number): string {
    const signedData = `${timestampSec}.${payloadJson}`;
    const digest = crypto.createHmac('sha256', secret).update(signedData, 'utf8').digest('hex');
    return `t=${timestampSec},v1=${digest}`;
  }

  verifySignature(
    payloadJson: string,
    secret: string,
    signatureHeader: string,
    toleranceSec = 300,
    nowSec = Math.floor(Date.now() / 1000)
  ): { valid: boolean; reason: string } {
    if (!signatureHeader || !signatureHeader.includes('v1=')) {
      return { valid: false, reason: 'Formato de cabecera X-HookRelay-Signature-256 inválido' };
    }

    const parts = Object.fromEntries(
      signatureHeader.split(',').map((kv) => {
        const [k, v] = kv.trim().split('=', 2);
        return [k, v || ''];
      })
    );

    const timestampSec = Number(parts.t);
    const providedHex = parts.v1 || '';
    if (!Number.isFinite(timestampSec) || !providedHex) {
      return { valid: false, reason: 'Timestamp o hash v1 ausente en la firma' };
    }

    if (Math.abs(nowSec - timestampSec) > toleranceSec) {
      return {
        valid: false,
        reason: `Firma expirada fuera de la ventana anti-replay (${toleranceSec}s)`,
      };
    }

    const expectedSignedData = `${timestampSec}.${payloadJson}`;
    const expectedHex = crypto
      .createHmac('sha256', secret)
      .update(expectedSignedData, 'utf8')
      .digest('hex');

    const bufProvided = Buffer.from(providedHex, 'utf8');
    const bufExpected = Buffer.from(expectedHex, 'utf8');

    if (bufProvided.length !== bufExpected.length) {
      return { valid: false, reason: 'Longitud de firma HMAC no coincide' };
    }

    const match = crypto.timingSafeEqual(bufProvided, bufExpected);
    return {
      valid: match,
      reason: match ? 'Firma HMAC-SHA256 auténtica e íntegra' : 'Firma HMAC-SHA256 inválida',
    };
  }
}

export const hmacSignerService = new HmacSignerService();
