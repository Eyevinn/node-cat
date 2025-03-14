import { CommonAccessToken, CommonAccessTokenFactory } from './cat';

export { CommonAccessToken } from './cat';

export type CatValidationTypes = 'mac' | 'sign' | 'none';

export interface CatValidationOptions {
  alg?: string;
  kid: string;
}

export interface CatGenerateOptions {
  type: CatValidationTypes;
  alg: string;
  kid: string;
}

export interface CatOptions {
  keys: { [keyid: string]: Buffer };
  expectCwtTag?: boolean;
}

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
    issuer: string,
    opts?: CatValidationOptions
  ) {
    const tokenWithoutPadding = token.trim();
    let cat;
    if (type == 'mac') {
      if (!opts) {
        throw new Error('Missing options for MAC validation');
      }
      const key = this.keys[opts.kid];
      if (!key) {
        throw new Error('Key not found');
      }
      cat = await CommonAccessTokenFactory.fromMacedToken(
        tokenWithoutPadding,
        {
          k: key,
          kid: opts.kid
        },
        this.expectCwtTag
      );
    } else {
      throw new Error('Unsupported validation type');
    }
    if (cat) {
      const valid = await cat.isValid(issuer);
      if (!valid) {
        throw new Error(`Invalid token: ${cat.reason}`);
      }
      return cat;
    }
  }

  public async generate(
    claims: { [key: string]: string | number },
    opts?: CatGenerateOptions
  ) {
    const cat = new CommonAccessToken(claims);
    if (opts && opts.type == 'mac') {
      const key = this.keys[opts.kid];
      if (!key) {
        throw new Error('Key not found');
      }
      const mac = await cat.mac({ k: key, kid: opts.kid }, opts.alg);
      if (!mac.raw) {
        throw new Error('Failed to MAC token');
      }
      return mac.raw.toString('base64');
    }
  }
}
