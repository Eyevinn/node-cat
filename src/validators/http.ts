import { IncomingMessage, OutgoingMessage } from 'node:http';
import { CAT } from '..';
import {
  InvalidAudienceError,
  InvalidIssuerError,
  KeyNotFoundError,
  TokenExpiredError,
  UriNotAllowedError
} from '../errors';
import {
  CloudFrontHeaders,
  CloudFrontRequest,
  CloudFrontResponse
} from 'aws-lambda';
import { CommonAccessTokenDict } from '../cat';

interface HttpValidatorKey {
  kid: string;
  key: Buffer;
}

export interface HttpValidatorOptions {
  tokenMandatory?: boolean;
  autoRenewEnabled?: boolean;
  tokenUriParam?: string;
  alg?: string;
  keys: HttpValidatorKey[];
  issuer: string;
  audience?: string[];
}

export interface HttpResponse {
  status: number;
  message?: string;
  claims?: CommonAccessTokenDict;
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
 *  // { status: 200, message: 'info', claims: { iss: 'eyevinn' } }
 */
export class HttpValidator {
  private keys: { [key: string]: Buffer } = {};
  private opts: HttpValidatorOptions;
  private tokenUriParam: string;

  constructor(opts: HttpValidatorOptions) {
    opts.keys.forEach((k: HttpValidatorKey) => {
      this.keys[k.kid] = k.key;
    });
    this.opts = opts;
    this.opts.tokenMandatory = opts.tokenMandatory ?? true;
    this.opts.autoRenewEnabled = opts.autoRenewEnabled ?? true;
    this.tokenUriParam = opts.tokenUriParam ?? 'cat';
  }

  public async validateCloudFrontRequest(
    cfRequest: CloudFrontRequest
  ): Promise<HttpResponse & { cfResponse: CloudFrontResponse }> {
    const requestLike: Pick<IncomingMessage, 'headers'> &
      Pick<IncomingMessage, 'url'> = {
      headers: {},
      url: ''
    };
    const response = new OutgoingMessage();

    if (cfRequest.headers) {
      Object.entries(cfRequest.headers).forEach(([name, header]) => {
        if (header && header.length > 0) {
          requestLike.headers[name.toLowerCase()] = header
            .map((h) => h.value)
            .join(',');
        }
      });
    }
    requestLike.url = cfRequest.uri;

    const result = await this.validateHttpRequest(
      requestLike as IncomingMessage,
      response
    );
    const cfHeaders: CloudFrontHeaders = {};
    Object.entries(response.getHeaders()).forEach(([name, value]) => {
      cfHeaders[name] = [{ key: name, value: value as string }];
    });
    const cfResponse: CloudFrontResponse = {
      status: result.status.toString(),
      statusDescription: result.message || 'ok',
      headers: cfHeaders
    };
    return { ...result, cfResponse: cfResponse };
  }

  public async validateHttpRequest(
    request: IncomingMessage,
    response?: OutgoingMessage
  ): Promise<HttpResponse> {
    const validator = new CAT({
      keys: this.keys
    });

    let url: URL | undefined = undefined;
    const host = request.headers.host;
    if (host) {
      url = new URL(`https://${host}${request.url}`);
    }

    let cat;
    const headerName = 'cta-common-access-token';
    let catrType;
    let token;

    // Check for token in headers first
    if (request.headers[headerName]) {
      token = Array.isArray(request.headers[headerName])
        ? request.headers[headerName][0]
        : request.headers[headerName];
      catrType = 'header';
    } else if (url && url.searchParams.has(this.tokenUriParam)) {
      token = url.searchParams.get(this.tokenUriParam);
      catrType = 'query';
    }
    if (token) {
      try {
        const result = await validator.validate(token, 'mac', {
          issuer: this.opts.issuer,
          audience: this.opts.audience,
          url
        });
        cat = result.cat;
        if (!result.error) {
          // CAT is acceptable
          if (
            cat &&
            cat?.shouldRenew &&
            this.opts.autoRenewEnabled &&
            response &&
            cat.keyId
          ) {
            // Renew token
            const renewedToken = await validator.renewToken(cat, {
              type: 'mac',
              issuer: this.opts.issuer,
              kid: cat.keyId,
              alg: this.opts.alg || 'HS256'
            });
            const catr = cat.claims.catr as any;
            if (
              catr.type === 'header' ||
              (catr.type === 'automatic' && catrType === 'header')
            ) {
              response.setHeader(
                catr['header-name'] || headerName,
                renewedToken +
                  (catr['header-params'] ? `;${catr['header-params']}` : '')
              );
            } else if (
              catr.type === 'cookie' ||
              (catr.type === 'automatic' && catrType === 'cookie')
            ) {
              const cookieName =
                catr['cookie-name'] || 'cta-common-access-token';
              response.setHeader(
                'Set-Cookie',
                `${cookieName}=${renewedToken}${
                  catr['cookie-params'] ? '; ' + catr['cookie-params'] : ''
                }`
              );
            } else if (
              catr.type === 'redirect' ||
              (catr.type === 'automatic' && catrType === 'query')
            ) {
              if (url) {
                const redirectUrl = url;
                redirectUrl.searchParams.delete(this.tokenUriParam);
                redirectUrl.searchParams.set(this.tokenUriParam, renewedToken);
                response.setHeader('Location', redirectUrl.toString());
              }
            }
          }
          return { status: 200, claims: cat?.claims };
        } else {
          return {
            status: 401,
            message: result.error.message,
            claims: cat?.claims
          };
        }
      } catch (err) {
        if (
          err instanceof InvalidIssuerError ||
          err instanceof InvalidAudienceError ||
          err instanceof KeyNotFoundError ||
          err instanceof TokenExpiredError ||
          err instanceof UriNotAllowedError
        ) {
          return {
            status: 401,
            message: (err as Error).message,
            claims: cat?.claims
          };
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
