import crypto from 'crypto';

const base16 = {
  encode(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }
};

export type MatchType =
  | 'exact-match'
  | 'prefix-match'
  | 'suffix-match'
  | 'contains-match'
  | 'regex-match'
  | 'sha256-match'
  | 'sha512-256-match';

export type MatchMap = Map<number, MatchValue>;
export type MatchValue = string | string[];

export const matchToLabels: { [key: string]: number } = {
  'exact-match': 0,
  'prefix-match': 1,
  'suffix-match': 2,
  'contains-match': 3,
  'regex-match': 4,
  'sha256-match': -1,
  'sha512-256-match': -2
};

export const labelsToMatch: { [key: number]: MatchType } = {
  0: 'exact-match',
  1: 'prefix-match',
  2: 'suffix-match',
  3: 'contains-match',
  4: 'regex-match',
  '-1': 'sha256-match',
  '-2': 'sha512-256-match'
};

export const matchTypeValidator: {
  [key: string]: (value: MatchValue) => boolean;
} = {
  'exact-match': (value: MatchValue) => typeof value === 'string',
  'prefix-match': (value: MatchValue) => typeof value === 'string',
  'suffix-match': (value: MatchValue) => typeof value === 'string',
  'contains-match': (value: MatchValue) => typeof value === 'string',
  'regex-match': (value: MatchValue) => Array.isArray(value),
  'sha256-match': (value: MatchValue) => typeof value === 'string',
  'sha512-256-match': (value: MatchValue) => typeof value === 'string'
};

export class MatchTypeError extends Error {
  constructor(message: string) {
    super(message);
  }
}
export async function match(
  value: string,
  matchType: MatchType,
  matchValue: MatchValue
) {
  switch (matchType) {
    case 'exact-match':
      if (Array.isArray(matchValue)) {
        throw new MatchTypeError('Exact match cannot be an array');
      }
      return value === matchValue;
    case 'prefix-match':
      if (Array.isArray(matchValue)) {
        throw new MatchTypeError('Prefix match cannot be an array');
      }
      return value.startsWith(matchValue);
    case 'suffix-match':
      if (Array.isArray(matchValue)) {
        throw new MatchTypeError('Suffix match cannot be an array');
      }
      return value.endsWith(matchValue);
    case 'contains-match':
      if (Array.isArray(matchValue)) {
        throw new MatchTypeError('Contains match cannot be an array');
      }
      return value.includes(matchValue);
    case 'regex-match': {
      if (!Array.isArray(matchValue)) {
        throw new MatchTypeError('Regex match must be an array');
      }
      const regex = new RegExp(matchValue[0], matchValue[1]);
      return regex.test(value);
    }
    case 'sha256-match': {
      if (Array.isArray(matchValue)) {
        throw new MatchTypeError('SHA256 match cannot be an array');
      }
      const encoded = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(value)
      );
      const encHex = base16.encode(new Uint8Array(encoded));
      return encHex === matchValue;
    }
    case 'sha512-256-match': {
      if (Array.isArray(matchValue)) {
        throw new MatchTypeError('SHA512-256 match cannot be an array');
      }
      const encoded512 = await crypto.subtle.digest(
        'SHA-512',
        new TextEncoder().encode(value)
      );
      const encHex512 = base16.encode(new Uint8Array(encoded512));
      return encHex512 === matchValue;
    }
    default:
      throw new MatchTypeError(`Unsupported match type: ${matchType}`);
  }
}
