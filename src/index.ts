import crypto from 'crypto';
import { CommonAccessToken, CommonAccessTokenFactory } from './cat';
import { KeyNotFoundError } from './errors';

export { CommonAccessToken } from './cat';
export { CommonAccessTokenRenewal } from './catr';
export { CommonAccessTokenUri } from './catu';

export { HttpValidator } from './validators/http';
export { ICTIStore } from './stores/interface';
export { MemoryCTIStore } from './stores/memory';
export { RedisCTIStore } from './stores/redis';

export type CatValidationTypes = 'mac' | 'sign' | 'none';

export interface CatValidationOptions {
  alg?: string;
  issuer: string;
  audience?: string[];
  url?: URL;
}

export interface CatGenerateOptions {
  type: CatValidationTypes;
  alg: string;
  kid: string;
  generateCwtId?: boolean;
}

export interface CatRenewOptions {
  type: CatValidationTypes;
  alg: string;
  kid: string;
  issuer: string;
}

export interface CatValidationResult {
  cat?: CommonAccessToken;
  error?: Error;
}

/**
 * Options for the CAT object
 *
 * @param {Object} keys - Key object
 * @param {boolean} expectCwtTag - Expect CWT tag in token
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
  keys: { [keyid: string]: Buffer };
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

  public async validate(
    token: string,
    type: CatValidationTypes,
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
        const valid = await cat.isValid(opts);
        if (valid) {
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
    if (opts?.generateCwtId) {
      claims['cti'] = crypto.randomBytes(16).toString('hex');
    }
    const cat = new CommonAccessToken(claims);
    if (opts && opts.type == 'mac') {
      const key = this.keys[opts.kid];
      if (!key) {
        throw new Error('Key not found');
      }
      await cat.mac({ k: key, kid: opts.kid }, opts.alg, {
        addCwtTag: this.expectCwtTag
      });
      if (!cat.raw) {
        throw new Error('Failed to MAC token');
      }
      return cat.raw.toString('base64');
    }
  }

  public async renewToken(
    cat: CommonAccessToken,
    opts: CatRenewOptions
  ): Promise<string> {
    const newClaims = cat.claims;
    newClaims['cti'] = crypto.randomBytes(16).toString('hex');
    newClaims['iat'] = Math.floor(Date.now() / 1000);
    newClaims['iss'] = opts.issuer;
    newClaims['exp'] = newClaims['iat'] + (newClaims['catr'] as any)['expadd'];
    const newCat = CommonAccessTokenFactory.fromDict(newClaims);

    const key = this.keys[opts.kid];
    if (!key) {
      throw new KeyNotFoundError();
    }
    await newCat.mac({ k: key, kid: opts.kid }, opts.alg, {
      addCwtTag: this.expectCwtTag
    });
    if (!newCat.raw) {
      throw new Error('Failed to MAC token');
    }
    return newCat.raw.toString('base64');
  }
}
