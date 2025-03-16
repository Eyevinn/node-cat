import { IncomingMessage } from 'node:http';
import { CAT } from '..';

interface HttpValidatorKey {
  kid: string;
  key: Buffer;
}

export interface HttpValidatorOptions {
  keys: HttpValidatorKey[];
  issuer: string;
}

export interface HttpResponse {
  status: number;
  message?: string;
}

/**
 * Handle request and validate CTA Common Access Token
 *
 * @example
 * const httpValidator = new HttpValidator({
 *   keys: [
 *     {
 *       kid: 'Symmetric256',
 *       key: Buffer.from(
 *         '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
 *         'hex'
 *       )
 *     }
 *   ],
 *   issuer: 'eyevinn'
 *  });
 *  const result = await httpValidator.validateHttpRequest(
 *    request,
 *    'Symmetric256'
 *  );
 *  // { status: 200, message: 'info' }
 */
export class HttpValidator {
  private keys: { [key: string]: Buffer } = {};
  private opts: HttpValidatorOptions;

  constructor(opts: HttpValidatorOptions) {
    opts.keys.forEach((k: HttpValidatorKey) => {
      this.keys[k.kid] = k.key;
    });
    this.opts = opts;
  }

  public async validateHttpRequest(
    request: IncomingMessage,
    kid: string
  ): Promise<HttpResponse> {
    const validator = new CAT({
      keys: this.keys
    });

    // Check for token in headers first
    if (request.headers['cta-common-access-token']) {
      const token = request.headers['cta-common-access-token'] as string;
      try {
        await validator.validate(token, 'mac', {
          kid,
          issuer: this.opts.issuer
        });
        return { status: 200 };
      } catch (err) {
        return { status: 401, message: (err as Error).message };
      }
    }
    throw new Error('No CTA token could be found');
  }
}
