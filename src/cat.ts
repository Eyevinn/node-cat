import * as cbor from 'cbor-x';
import cose from 'cose-js';
import {
  InvalidAudienceError,
  InvalidClaimTypeError,
  InvalidIssuerError,
  InvalidJsonError,
  RenewalClaimError,
  TokenExpiredError,
  TokenNotActiveError,
  UriNotAllowedError
} from './errors';
import { CatValidationOptions } from '.';
import { CommonAccessTokenUri } from './catu';
import { CommonAccessTokenRenewal } from './catr';
import { CommonAccessTokenHeader } from './cath';
import { CommonAccessTokenIf } from './catif';
import { toBase64, toHex } from './util';
import { Log } from './log';

export const claimsToLabels: { [key: string]: number } = {
  iss: 1, // 3
  sub: 2, // 3
  aud: 3, // 3
  exp: 4, // 6 tag value 1
  nbf: 5, // 6 tag value 1
  iat: 6, // 6 tag value 1
  cti: 7, // 2,
  cnf: 8,
  geohash: 282,
  catreplay: 308,
  catpor: 309,
  catv: 310,
  catnip: 311,
  catu: 312,
  catm: 313,
  catalpn: 314,
  cath: 315,
  catgeoiso3166: 316,
  catgeocoord: 317,
  cattpk: 319,
  catifdata: 320,
  catadpop: 321,
  catif: 322,
  catr: 323
};

export const labelsToClaim: { [key: number]: string } = {
  1: 'iss',
  2: 'sub',
  3: 'aud',
  4: 'exp',
  5: 'nbf',
  6: 'iat',
  7: 'cti',
  8: 'cnf',
  282: 'geohash',
  308: 'catreplay',
  309: 'catpor',
  310: 'catv',
  311: 'catnip',
  312: 'catu',
  313: 'catm',
  314: 'catalpn',
  315: 'cath',
  316: 'catgeoiso3166',
  317: 'catgeocoord',
  319: 'cattpk',
  320: 'catifdata',
  321: 'catadpop',
  322: 'catif',
  323: 'catr'
};

const claimTransform: { [key: string]: (value: string) => Buffer } = {
  cti: (value: unknown) =>
    value instanceof Uint8Array
      ? Buffer.from(value)
      : Buffer.from(value as string, 'hex'),
  cattpk: (value) => Buffer.from(value, 'hex')
};

const claimTransformReverse: { [key: string]: (value: Buffer) => string } = {
  cti: (value: Buffer) => toHex(value),
  cattpk: (value: Buffer) => toHex(value)
};

const claimTypeValidators: {
  [key: string]: (value: CommonAccessTokenValue) => boolean;
} = {
  iss: (value) => typeof value === 'string',
  exp: (value) => typeof value === 'number',
  aud: (value) => typeof value === 'string' || Array.isArray(value),
  nbf: (value) => typeof value === 'number',
  cti: (value) => Buffer.isBuffer(value),
  catreplay: (value) => typeof value === 'number',
  catpor: (value) => Array.isArray(value),
  catv: (value) => typeof value === 'number' && value >= 1,
  catnip: (value) => typeof value === 'number' || typeof value === 'string',
  catu: (value) => value instanceof Map,
  catm: (value) => Array.isArray(value),
  cath: (value) => value instanceof Map,
  catgeoiso3166: (value) => Array.isArray(value),
  catgeocoord: (value) => Array.isArray(value),
  cattpk: (value) => Buffer.isBuffer(value),
  sub: (value) => typeof value === 'string',
  iat: (value) => typeof value === 'number',
  catifdata: (value) => typeof value === 'string' || Array.isArray(value),
  cnf: (value) => value instanceof Map,
  catdpop: (value) => value instanceof Map,
  catif: (value) => value instanceof Map,
  catr: (value) => value instanceof Map
};

const isHex = (value: string) => /^[0-9a-fA-F]+$/.test(value);
const isNetworkIp = (value: string) => /^[0-9a-fA-F:.]+$/.test(value);

const claimTypeDictValidators: {
  [key: string]: (value: unknown) => boolean;
} = {
  iss: (value) => typeof value === 'string',
  exp: (value) => typeof value === 'number',
  aud: (value) => typeof value === 'string' || Array.isArray(value),
  nbf: (value) => typeof value === 'number',
  cti: (value) => typeof value === 'string' && isHex(value),
  catreplay: (value) => typeof value === 'number' && value >= 0,
  catpor: (value) => Array.isArray(value),
  catv: (value) => typeof value === 'number' && value >= 1,
  catnip: (value) =>
    typeof value === 'number' ||
    (typeof value === 'string' && isNetworkIp(value)),
  catu: (value) => typeof value === 'object',
  catm: (value) => Array.isArray(value),
  cath: (value) => typeof value === 'object',
  catgeoiso3166: (value) => Array.isArray(value),
  catgeocoord: (value) => Array.isArray(value),
  catgeoalt: (value) => Array.isArray(value),
  cattpk: (value) => typeof value === 'string' && isHex(value),
  sub: (value) => typeof value === 'string',
  iat: (value) => typeof value === 'number',
  catifdata: (value) => typeof value === 'string' || Array.isArray(value),
  cnf: (value) => typeof value === 'object',
  catdpop: (value) => typeof value === 'object',
  catif: (value) => typeof value === 'object',
  catr: (value) => typeof value === 'object'
};

const CWT_TAG = 61;

/**
 * Common Access Token Claims
 */
export type CommonAccessTokenClaims = {
  [key: string]: string | number | Map<number | string, any>;
};
export type CommonAccessTokenDict = {
  [key: string]: string | number | { [key: string]: any };
};
export type CommonAccessTokenValue =
  | string
  | number
  | Buffer
  | Map<number | string, any>;

/**
 * CWT Encryption Key
 */
export interface CWTEncryptionKey {
  /**
   * Key
   */
  k: Buffer;
  /**
   * Key ID
   */
  kid: string;
}

/**
 * CWT Decryption Key
 */
export interface CWTDecryptionKey {
  /**
   * Key
   */
  k: Buffer;
  /**
   * Key ID
   */
  kid: string;
}

export interface CWTSigningKey {
  d: Buffer;
  kid: string;
}
export interface CWTVerifierKey {
  x: Buffer;
  y: Buffer;
  kid: string;
}

function updateMapFromClaims(
  claims: CommonAccessTokenClaims
): Map<number, CommonAccessTokenValue> {
  const map = new Map<number, CommonAccessTokenValue>();

  let dict = claims;
  if (claims instanceof Map) {
    dict = Object.fromEntries(claims);
  }
  for (const param in dict) {
    const key = claimsToLabels[param] ? claimsToLabels[param] : parseInt(param);
    if (key === claimsToLabels['catu'] && !(dict[param] instanceof Map)) {
      map.set(
        key,
        CommonAccessTokenUri.fromDictTags(dict[param] as any).payload
      );
    } else if (
      key === claimsToLabels['catr'] &&
      !(dict[param] instanceof Map)
    ) {
      map.set(
        key,
        CommonAccessTokenRenewal.fromDictTags(dict[param] as any).payload
      );
    } else if (
      key === claimsToLabels['cath'] &&
      !(dict[param] instanceof Map)
    ) {
      map.set(
        key,
        CommonAccessTokenHeader.fromDictTags(dict[param] as any).payload
      );
    } else if (
      key === claimsToLabels['catif'] &&
      !(dict[param] instanceof Map)
    ) {
      map.set(
        key,
        CommonAccessTokenIf.fromDictTags(dict[param] as any).payload
      );
    } else {
      const k = param.match(/\d+/) ? labelsToClaim[parseInt(param)] : param;
      const value = claimTransform[k]
        ? claimTransform[k](dict[param] as string)
        : dict[param];
      map.set(key, value);
    }
  }
  return map;
}

function updateMapFromDict(
  dict: CommonAccessTokenDict
): CommonAccessTokenClaims {
  const claims: CommonAccessTokenClaims = {};
  for (const param in dict) {
    if (
      claimTypeDictValidators[param] &&
      !claimTypeDictValidators[param](dict[param])
    ) {
      throw new InvalidJsonError(param);
    }
    const key = claimsToLabels[param];
    if (param === 'catu') {
      claims[key] = CommonAccessTokenUri.fromDict(
        dict[param] as { [key: string]: any }
      ).payload;
    } else if (param === 'catr') {
      claims[key] = CommonAccessTokenRenewal.fromDict(
        dict[param] as { [key: string]: any }
      ).payload;
    } else if (param == 'cath') {
      claims[key] = CommonAccessTokenHeader.fromDict(
        dict[param] as { [key: string]: any }
      ).payload;
    } else if (param == 'catif') {
      claims[key] = CommonAccessTokenIf.fromDict(
        dict[param] as { [key: string]: any }
      ).payload;
    } else {
      const value = claimTransform[param]
        ? claimTransform[param](dict[param] as string)
        : dict[param];
      claims[key] = value as string | number;
    }
  }
  return claims;
}

/**
 * Common Access Token
 */
export class CommonAccessToken {
  private payload: Map<number, CommonAccessTokenValue>;
  private data?: Buffer;
  private kid?: string;

  constructor(claims: CommonAccessTokenClaims) {
    this.payload = updateMapFromClaims(claims);
    if (!this.payload.has(claimsToLabels['catv'])) {
      this.payload.set(claimsToLabels['catv'], 1);
    }
    this.validateTypes();
  }

  /**
   * Create a CWT CAT token
   */
  public async mac(
    /**
     * Encryption key
     */
    key: CWTEncryptionKey,
    /**
     * Algorithm to use
     */
    alg: string,
    /**
     * Options
     */
    opts?: {
      noCwtTag: boolean;
    }
  ): Promise<void> {
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const recipient = {
      key: key.k
    };
    if (!opts?.noCwtTag) {
      const plaintext = cbor.encode(this.payload);
      const coseMessage = await cose.mac.create(
        headers,
        plaintext as unknown as string,
        recipient
      );
      const decoder = new cbor.Decoder({ mapsAsObjects: false });
      const decoded = decoder.decode(coseMessage).value;
      const coseTag = new cbor.Tag(decoded, 17);
      const cwtTag = new cbor.Tag(coseTag, CWT_TAG);
      this.data = cbor.encode(cwtTag);
    } else {
      const plaintext = cbor.encode(this.payload).toString('hex');
      this.data = await cose.mac.create(headers, plaintext, recipient);
    }
    this.kid = key.kid;
  }

  /**
   * Parse a CWT CAT token
   */
  public async parse(
    token: Buffer,
    key: CWTDecryptionKey,
    opts?: {
      expectCwtTag: boolean;
    }
  ): Promise<void> {
    const decoder = new cbor.Decoder({ mapsAsObjects: false });
    const coseMessage = decoder.decode(token);
    Log(coseMessage, { depth: null });
    if (opts?.expectCwtTag && coseMessage.tag !== 61) {
      throw new Error('Expected CWT tag');
    }
    if (coseMessage.tag === CWT_TAG) {
      const cborCoseMessage = cbor.encode(coseMessage.value);
      Log({
        kid: key.kid,
        key: key.k.toString('hex')
      });
      const buf = await cose.mac.read(cborCoseMessage, key.k);
      const json = await decoder.decode(buf);
      this.payload = updateMapFromClaims(json);
    } else {
      const buf = await cose.mac.read(token, key.k);
      this.payload = await decoder.decode(
        Buffer.from(buf.toString('hex'), 'hex')
      );
    }
    this.kid = key.kid;
  }

  public async sign(key: CWTSigningKey, alg: string): Promise<void> {
    const plaintext = cbor.encode(this.payload).toString('hex');
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const signer = {
      key: key
    };
    this.data = await cose.sign.create(headers, plaintext, signer);
  }

  public async verify(
    token: Buffer,
    key: CWTVerifierKey
  ): Promise<CommonAccessToken> {
    const buf = await cose.sign.verify(token, { key: key });
    this.payload = await cbor.decode(Buffer.from(buf.toString('hex'), 'hex'));
    return this;
  }

  private async validateTypes() {
    for (const [key, value] of this.payload) {
      const claim = labelsToClaim[key];
      if (value && claimTypeValidators[claim]) {
        if (!claimTypeValidators[claim](value)) {
          throw new InvalidClaimTypeError(claim, value);
        }
      }
    }
  }

  /**
   * Token is valid and acceptable
   */
  public async isAcceptable(opts: CatValidationOptions): Promise<boolean> {
    this.validateTypes();

    if (
      this.payload.get(claimsToLabels['iss']) &&
      this.payload.get(claimsToLabels['iss']) !== opts.issuer
    ) {
      throw new InvalidIssuerError(this.payload.get(claimsToLabels['iss']));
    }
    if (
      this.payload.get(claimsToLabels['exp']) &&
      (this.payload.get(claimsToLabels['exp']) as number) < Date.now() / 1000
    ) {
      throw new TokenExpiredError();
    }
    if (opts.audience) {
      const value = this.payload.get(claimsToLabels['aud']);
      if (value) {
        const claimAud = Array.isArray(value) ? value : [value];
        if (!opts.audience.some((item) => claimAud.includes(item))) {
          throw new InvalidAudienceError(claimAud as string[]);
        }
      }
    }
    if (
      this.payload.get(claimsToLabels['nbf']) &&
      (this.payload.get(claimsToLabels['nbf']) as number) >
        Math.floor(Date.now() / 1000)
    ) {
      throw new TokenNotActiveError();
    }
    if (this.payload.get(claimsToLabels['catu'])) {
      const catu = CommonAccessTokenUri.fromMap(
        this.payload.get(claimsToLabels['catu']) as Map<number, any>
      );
      if (!opts.url) {
        throw new UriNotAllowedError('No URL provided');
      }
      if (!(await catu.match(opts.url))) {
        throw new UriNotAllowedError(`URI ${opts.url} not allowed`);
      }
    }
    if (this.payload.get(claimsToLabels['catr'])) {
      const catr = CommonAccessTokenRenewal.fromMap(
        this.payload.get(claimsToLabels['catr']) as Map<number, any>
      );
      if (!catr.isValid()) {
        throw new RenewalClaimError('Invalid renewal claim');
      }
    }

    return true;
  }

  get shouldRenew(): boolean {
    const exp = this.payload.get(claimsToLabels['exp']) as number;
    if (exp) {
      const catr = this.payload.get(claimsToLabels['catr']);
      if (catr) {
        const renewal = CommonAccessTokenRenewal.fromMap(
          catr as Map<number, any>
        ).toDict();
        const now = Math.floor(Date.now() / 1000);
        let lowThreshold = exp - 1 * 60;
        if (renewal.deadline !== undefined) {
          lowThreshold = exp - renewal.deadline;
        }
        //console.log(`${now} >= ${lowThreshold} && ${now} < ${exp}`);
        if (now >= lowThreshold && now < exp) {
          return true;
        }
      }
    }
    return false;
  }

  get cti(): string | undefined {
    const tokenId = this.payload.get(claimsToLabels['cti']);
    if (tokenId) {
      return claimTransformReverse['cti'](tokenId as Buffer);
    }
    return undefined;
  }

  get claims(): CommonAccessTokenDict {
    const result: CommonAccessTokenDict = {};
    this.payload.forEach((value, param) => {
      const key = labelsToClaim[param] ? labelsToClaim[param] : param;
      if (key === 'catu') {
        result[key] = CommonAccessTokenUri.fromMap(
          value as Map<number, any>
        ).toDict();
      } else if (key === 'catr') {
        result[key] = CommonAccessTokenRenewal.fromMap(
          value as Map<number, any>
        ).toDict();
      } else if (key === 'cath') {
        result[key] = CommonAccessTokenHeader.fromMap(
          value as Map<string, any>
        ).toDict();
      } else if (key === 'catif') {
        result[key] = CommonAccessTokenIf.fromMap(
          value as Map<number, any>
        ).toDict();
      } else {
        const theValue = claimTransformReverse[key]
          ? claimTransformReverse[key](value as Buffer)
          : (value as string | number);
        result[key] = theValue;
      }
    });
    return result;
  }

  get raw() {
    return this.data;
  }

  get base64() {
    return this.data ? toBase64(this.data) : undefined;
  }

  get keyId() {
    return this.kid;
  }
}

/**
 * Common Access Token Factory
 */
export class CommonAccessTokenFactory {
  public static async fromSignedToken(
    base64encoded: string,
    key: CWTVerifierKey
  ): Promise<CommonAccessToken> {
    const token = Buffer.from(base64encoded, 'base64');
    const cat = new CommonAccessToken({});
    await cat.verify(token, key);
    return cat;
  }

  public static async fromMacedToken(
    base64encoded: string,
    key: CWTDecryptionKey,
    expectCwtTag: boolean
  ): Promise<CommonAccessToken> {
    const token = Buffer.from(base64encoded, 'base64');
    const cat = new CommonAccessToken({});
    await cat.parse(token, key, { expectCwtTag });
    return cat;
  }

  public static fromDict(claims: CommonAccessTokenDict) {
    const cat = new CommonAccessToken(updateMapFromDict(claims));
    return cat;
  }
}
