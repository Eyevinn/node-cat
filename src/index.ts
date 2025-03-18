import crypto from 'crypto';
import { CommonAccessToken, CommonAccessTokenFactory } from './cat';
import { KeyNotFoundError } from './errors';

export { CommonAccessToken } from './cat';
export { HttpValidator } from './validators/http';

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
  ) {
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
      const valid = await cat.isValid(opts);
      if (valid) {
        return cat;
      }
    }
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
}
