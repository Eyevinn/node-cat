import {
  CommonAccessToken,
  CommonAccessTokenDict,
  CommonAccessTokenFactory
} from './cat';
import { KeyNotFoundError } from './errors';
import { generateRandomHex, toBase64NoPadding } from './util';

export { CommonAccessToken } from './cat';
export { CommonAccessTokenRenewal } from './catr';
export { CommonAccessTokenUri } from './catu';

export { HttpValidator } from './validators/http';
export { ICTIStore } from './stores/interface';
export { MemoryCTIStore } from './stores/memory';
export { RedisCTIStore } from './stores/redis';

export { ITokenLogger } from './loggers/interface';
export { ConsoleLogger } from './loggers/console';

/**
 * Types of CAT validation
 */
export type CatValidationTypes = 'mac' | 'sign' | 'none';

/**
 * Options for the CAT validation
 */
export interface CatValidationOptions {
  /**
   * Algorithm to use for validation
   */
  alg?: string;
  /**
   * Expected issuer of token
   */
  issuer: string;
  /**
   * Allowed audiences for token
   */
  audience?: string[];
  /**
   * Request URL associated with the token
   */
  url?: URL;
}

/**
 * Options for generating a CAT token
 */
export interface CatGenerateOptions {
  /**
   * Type of validation mechanism to use for the token
   */
  type: CatValidationTypes;
  /**
   * Algorithm to use for token generation
   */
  alg: string;
  /**
   * Key ID to use for token generation
   */
  kid: string;
  /**
   * Whether to generate a CWT ID for the token
   */
  generateCwtId?: boolean;
}

export interface CatRenewOptions {
  type: CatValidationTypes;
  alg: string;
  kid: string;
  issuer: string;
}

/**
 * Result of the CAT validation
 */
export interface CatValidationResult {
  /**
   * The CAT object
   */
  cat?: CommonAccessToken;
  /**
   * Error if any
   */
  error?: Error;
}

/**
 * Options for the CAT object
 *
 * @example
 * const opts = {
 *   keys: {
 *     Symmetric256: Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex')
 *   },
 *   expectCwtTag: true
 * };
 */
export interface CatOptions {
  /**
   * Key ID to key mapping
   */
  keys: { [keyid: string]: Buffer };

  /**
   * Whether there should be a CWT tag in the token
   */
  expectCwtTag?: boolean;
}

/**
 * Common Access Token (CAT) validator and generator
 *
 * @param {CatOptions} opts - Options for the CAT object
 *
 * @example
 * const validator = new CAT({
 *   keys: {
 *     Symmetric256: Buffer.from(
 *       '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
 *       'hex'
 *     )
 *   },
 * });
 * try {
 *   await validator.validate(base64encoded, 'mac', {
 *     kid: 'Symmetric256',
 *     issuer: 'coap://as.example.com'
 *   });
 * } catch (e) {
 *   // Not valid, handle error
 * }
 */
export class CAT {
  private keys: { [keyid: string]: Buffer };
  private expectCwtTag = false;

  constructor(opts: CatOptions) {
    this.keys = opts.keys;
    this.expectCwtTag = opts.expectCwtTag || false;
  }

  /**
   * Validate a CAT token
   * @async
   *
   * @example
   * try {
   *   await validator.validate(base64encoded, 'mac', {
   *     kid: 'Symmetric256',
   *     issuer: 'coap://as.example.com'
   *   });
   * } catch (e) {
   *   // Not valid, handle error
   * }
   */
  public async validate(
    /**
     * The token to validate (base64 encoded)
     */
    token: string,
    /**
     * Type of validation to perform
     */
    type: CatValidationTypes,
    /**
     * Options for the validation
     */
    opts: CatValidationOptions
  ): Promise<CatValidationResult> {
    const tokenWithoutPadding = token.trim();
    let cat;
    if (type == 'mac') {
      if (!opts) {
        throw new Error('Missing options for MAC validation');
      }
      let error;
      for (const kid in this.keys) {
        try {
          const key = this.keys[kid];
          cat = await CommonAccessTokenFactory.fromMacedToken(
            tokenWithoutPadding,
            {
              k: key,
              kid: kid
            },
            this.expectCwtTag
          );
          if (cat && cat.claims) {
            error = undefined;
            break;
          }
        } catch (err) {
          error = err;
        }
      }
      if (error) {
        if ((error as Error).message === 'Tag mismatch') {
          throw new KeyNotFoundError();
        } else {
          throw error;
        }
      }
    } else {
      throw new Error('Unsupported validation type');
    }
    if (cat) {
      try {
        const acceptable = await cat.isAcceptable(opts);
        if (acceptable) {
          return { cat, error: undefined };
        }
      } catch (err) {
        return { cat, error: err as Error };
      }
    }
    return { error: new Error('Unable to parse token') };
  }

  public async generate(
    claims: { [key: string]: string | number | Map<number, any> },
    opts?: CatGenerateOptions
  ) {
    if (opts?.generateCwtId && !claims['cti']) {
      claims['cti'] = generateRandomHex(16);
    }
    const cat = new CommonAccessToken(claims);
    if (opts && opts.type == 'mac') {
      const key = this.keys[opts.kid];
      if (!key) {
        throw new Error('Key not found');
      }
      await cat.mac({ k: key, kid: opts.kid }, opts.alg, {
        noCwtTag: !this.expectCwtTag
      });
      if (!cat.raw) {
        throw new Error('Failed to MAC token');
      }
      return toBase64NoPadding(cat.raw);
    }
  }

  /**
   * Generate a CAT token from a JSON object
   *
   * @example
   * const base64encoded = await generator.generateFromJson(
   *   {
   *     iss: 'coap://as.example.com',
   *     sub: 'jonas',
   *     aud: 'coap://light.example.com',
   *     exp: 1444064944,
   *     nbf: 1443944944,
   *     iat: 1443944944,
   *     catr: {
   *       type: 'header',
   *       'header-name': 'cta-common-access-token',
   *       expadd: 120,
   *       deadline: 60
   *     }
   *   },
   *   {
   *     type: 'mac',
   *     alg: 'HS256',
   *     kid: 'Symmetric256',
   *     generateCwtId: true // automatically generate a random CWT Id (cti) claim (default: false)
   *   }
   * );
   */
  public async generateFromJson(
    /**
     * The claims to use for the token
     */
    dict: CommonAccessTokenDict,
    /**
     * Options for the token generation
     */
    opts?: CatGenerateOptions
  ) {
    if (opts?.generateCwtId && !dict['cti']) {
      dict['cti'] = generateRandomHex(16);
    }
    const cat = CommonAccessTokenFactory.fromDict(dict);
    if (opts && opts.type == 'mac') {
      const key = this.keys[opts.kid];
      if (!key) {
        throw new Error('Key not found');
      }
      await cat.mac({ k: key, kid: opts.kid }, opts.alg, {
        noCwtTag: !this.expectCwtTag
      });
      if (!cat.raw) {
        throw new Error('Failed to MAC token');
      }
      return toBase64NoPadding(cat.raw);
    }
  }

  /**
   * Renew a CAT token
   */
  public async renewToken(
    /**
     * The token to renew
     */
    cat: CommonAccessToken,
    /**
     * Options for the renewal
     */
    opts: CatRenewOptions
  ): Promise<string> {
    const newClaims = cat.claims;
    newClaims['cti'] = generateRandomHex(16);
    newClaims['iat'] = Math.floor(Date.now() / 1000);
    newClaims['iss'] = opts.issuer;
    newClaims['exp'] = newClaims['iat'] + (newClaims['catr'] as any)['expadd'];
    const newCat = CommonAccessTokenFactory.fromDict(newClaims);

    const key = this.keys[opts.kid];
    if (!key) {
      throw new KeyNotFoundError();
    }
    await newCat.mac({ k: key, kid: opts.kid }, opts.alg, {
      noCwtTag: !this.expectCwtTag
    });
    if (!newCat.raw) {
      throw new Error('Failed to MAC token');
    }
    return toBase64NoPadding(newCat.raw);
  }
}
