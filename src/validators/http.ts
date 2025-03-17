import { IncomingMessage } from 'node:http';
import { CAT } from '..';
import {
  InvalidAudienceError,
  InvalidIssuerError,
  KeyNotFoundError,
  TokenExpiredError
} from '../errors';
import { CloudFrontRequest } from 'aws-lambda';

interface HttpValidatorKey {
  kid: string;
  key: Buffer;
}

export interface HttpValidatorOptions {
  tokenMandatory?: boolean;
  keys: HttpValidatorKey[];
  issuer: string;
  audience?: string[];
}

export interface HttpResponse {
  status: number;
  message?: string;
}

export class NoTokenFoundError extends Error {
  constructor() {
    super('No CTA token could be found');
  }
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
 *   audience: ['one', 'two'] // Optional
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
    this.opts.tokenMandatory = opts.tokenMandatory ?? true;
  }

  public async validateCloudFrontRequest(
    cfRequest: CloudFrontRequest
  ): Promise<HttpResponse> {
    const requestLike: Pick<IncomingMessage, 'headers'> = {
      headers: {}
    };

    if (cfRequest.headers) {
      Object.entries(cfRequest.headers).forEach(([name, header]) => {
        if (header && header.length > 0) {
          requestLike.headers[name.toLowerCase()] = header
            .map((h) => h.value)
            .join(',');
        }
      });
    }

    return await this.validateHttpRequest(requestLike as IncomingMessage);
  }

  public async validateHttpRequest(
    request: IncomingMessage
  ): Promise<HttpResponse> {
    const validator = new CAT({
      keys: this.keys
    });

    // Check for token in headers first
    if (request.headers['cta-common-access-token']) {
      const token = Array.isArray(request.headers['cta-common-access-token'])
        ? request.headers['cta-common-access-token'][0]
        : request.headers['cta-common-access-token'];
      try {
        await validator.validate(token, 'mac', {
          issuer: this.opts.issuer,
          audience: this.opts.audience
        });
        return { status: 200 };
      } catch (err) {
        if (
          err instanceof InvalidIssuerError ||
          err instanceof InvalidAudienceError ||
          err instanceof KeyNotFoundError ||
          err instanceof TokenExpiredError
        ) {
          return { status: 401, message: (err as Error).message };
        } else {
          console.log(`Internal error`, err);
          return { status: 500, message: (err as Error).message };
        }
      }
    }
    if (this.opts.tokenMandatory) {
      throw new NoTokenFoundError();
    }
    return { status: 200 };
  }
}
