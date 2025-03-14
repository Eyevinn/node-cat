import * as cbor from 'cbor-x';
import cose from 'cose-js';

const claimsToLabels: { [key: string]: number } = {
  iss: 1, // 3
  sub: 2, // 3
  aud: 3, // 3
  exp: 4, // 6 tag value 1
  nbf: 5, // 6 tag value 1
  iat: 6, // 6 tag value 1
  cti: 7 // 2
};

const labelsToClaim: { [key: number]: string } = {
  1: 'iss',
  2: 'sub',
  3: 'aud',
  4: 'exp',
  5: 'nbf',
  6: 'iat',
  7: 'cti'
};

const claimTransform: { [key: string]: (value: string) => Buffer } = {
  cti: (value) => Buffer.from(value, 'hex')
};

const claimTransformReverse: { [key: string]: (value: Buffer) => string } = {
  cti: (value: Buffer) => value.toString('hex')
};

export type CommonAccessTokenClaims = { [key: string]: string | number };

export interface CWTEncryptionKey {
  k: Buffer;
  kid: string;
}
export interface CWTDecryptionKey {
  k: Buffer;
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

export class CommonAccessToken {
  private payload: Map<number, string | number | Buffer>;
  private data?: Buffer;

  constructor(claims: CommonAccessTokenClaims) {
    this.payload = new Map<number, string | number>();
    for (const param in claims) {
      const key = claimsToLabels[param]
        ? claimsToLabels[param]
        : parseInt(param);
      const value = claimTransform[param]
        ? claimTransform[param](claims[param] as string)
        : claims[param];
      this.payload.set(key, value);
    }
  }

  public async mac(
    key: CWTEncryptionKey,
    alg: string
  ): Promise<CommonAccessToken> {
    const plaintext = cbor.encode(this.payload).toString('hex');
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const recipient = {
      key: key.k
    };
    this.data = await cose.mac.create(headers, plaintext, recipient);
    return this;
  }

  public async parse(
    token: Buffer,
    key: CWTDecryptionKey
  ): Promise<CommonAccessToken> {
    const buf = await cose.mac.read(token, key.k);
    this.payload = await cbor.decode(Buffer.from(buf.toString('hex'), 'hex'));
    return this;
  }

  public async sign(
    key: CWTSigningKey,
    alg: string
  ): Promise<CommonAccessToken> {
    const plaintext = cbor.encode(this.payload).toString('hex');
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const signer = {
      key: key
    };
    this.data = await cose.sign.create(headers, plaintext, signer);
    return this;
  }

  public async verify(
    token: Buffer,
    key: CWTVerifierKey
  ): Promise<CommonAccessToken> {
    const buf = await cose.sign.verify(token, { key: key });
    this.payload = await cbor.decode(Buffer.from(buf.toString('hex'), 'hex'));
    return this;
  }

  get(key: string) {
    const theKey = claimsToLabels[key] ? claimsToLabels[key] : parseInt(key);
    return this.payload.get(theKey);
  }

  get claims() {
    const result: { [key: string]: string | number } = {};
    this.payload.forEach((value, param) => {
      const key = labelsToClaim[param] ? labelsToClaim[param] : param;
      const theValue = claimTransformReverse[key]
        ? claimTransformReverse[key](value as Buffer)
        : (value as string | number);
      result[key] = theValue;
    });
    return result;
  }

  get raw() {
    return this.data;
  }
}
