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
}

export class CAT {
  private keys: { [keyid: string]: Buffer };

  constructor(opts: CatOptions) {
    this.keys = opts.keys;
  }

  public async validate(
    token: string,
    type: CatValidationTypes,
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
      cat = CommonAccessTokenFactory.fromMacedToken(tokenWithoutPadding, {
        k: key,
        kid: opts.kid
      });
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
