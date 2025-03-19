import { IncomingMessage, OutgoingMessage } from 'node:http';
import { CAT, CommonAccessToken } from '..';
import {
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidReuseDetected,
  KeyNotFoundError,
  ReplayNotAllowedError,
  TokenExpiredError,
  UriNotAllowedError
} from '../errors';
import {
  CloudFrontHeaders,
  CloudFrontRequest,
  CloudFrontResponse
} from 'aws-lambda';
import { CommonAccessTokenDict } from '../cat';
import { ICTIStore } from '../stores/interface';
import { ITokenLogger } from '../loggers/interface';

interface HttpValidatorKey {
  kid: string;
  key: Buffer;
}

/**
 * Options for the HttpValidator
 */
export interface HttpValidatorOptions {
  /**
   * If token is mandatory to be present in the request
   */
  tokenMandatory?: boolean;
  /**
   * If token should be automatically renewed according to CATR
   */
  autoRenewEnabled?: boolean;
  /**
   * Name of the query parameter to look for token
   */
  tokenUriParam?: string;
  /**
   * Algorithm to use for token validation
   */
  alg?: string;
  /**
   * Keys to use for token validation
   */
  keys: HttpValidatorKey[];
  /**
   * Expected issuer of token
   */
  issuer: string;
  /**
   * Allowed audiences for token
   */
  audience?: string[];
  /**
   * Store for tracking token usage
   */
  store?: ICTIStore;
  /**
   * Logger for logging token usage
   */
  logger?: ITokenLogger;
  /**
   * Callback for reuse detection
   */
  reuseDetection?: (
    cat: CommonAccessToken,
    store?: ICTIStore,
    logger?: ITokenLogger
  ) => Promise<boolean>;
}

/**
 * Response from the HttpValidator
 */
export interface HttpResponse {
  /**
   * HTTP status code
   */
  status: number;
  /**
   * Optional message
   */
  message?: string;
  /**
   * Claims from the token
   */
  claims?: CommonAccessTokenDict;
  /**
   * Number of times token has been used
   */
  count?: number;
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
 *   issuer: 'eyevinn',
 *   audience: ['one', 'two'], // Optional
 *   store: new MemoryCTIStore() // Optional store for tracking token usage
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
  private store?: ICTIStore;
  private logger?: ITokenLogger;

  constructor(opts: HttpValidatorOptions) {
    opts.keys.forEach((k: HttpValidatorKey) => {
      this.keys[k.kid] = k.key;
    });
    this.opts = opts;
    this.opts.tokenMandatory = opts.tokenMandatory ?? true;
    this.opts.autoRenewEnabled = opts.autoRenewEnabled ?? true;
    this.tokenUriParam = opts.tokenUriParam ?? 'cat';
    this.store = opts.store;
    this.logger = opts.logger;
  }

  /**
   * Validate a CloudFront request
   */
  public async validateCloudFrontRequest(
    /**
     * CloudFront request
     */
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

  /**
   * Validate a HTTP request
   */
  public async validateHttpRequest(
    /**
     * HTTP request
     */
    request: IncomingMessage,
    /**
     * HTTP response to set headers on
     */
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
          let count;
          // CAT is acceptable
          if (cat && this.store) {
            count = await this.store.storeToken(cat);
            if (cat.claims.catreplay !== undefined) {
              if (cat.claims.catreplay === 1) {
                if (count > 1) {
                  throw new ReplayNotAllowedError(count);
                }
              } else if (
                cat.claims.catreplay === 2 &&
                this.opts.reuseDetection
              ) {
                if (
                  await this.opts.reuseDetection(cat, this.store, this.logger)
                ) {
                  throw new InvalidReuseDetected();
                }
              }
            }
          }
          if (cat && this.logger) {
            await this.logger.logToken(cat);
          }
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
          return { status: 200, claims: cat?.claims, count };
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
          err instanceof UriNotAllowedError ||
          err instanceof ReplayNotAllowedError ||
          err instanceof InvalidReuseDetected
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
