import crypto from 'crypto';
import { InvalidCatuError } from './errors';

const base16 = {
  encode(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }
};

type UriPart =
  | 'scheme'
  | 'host'
  | 'port'
  | 'path'
  | 'query'
  | 'parent-path'
  | 'filename'
  | 'stem'
  | 'extension';

const uriPartToLabels: { [key: string]: number } = {
  scheme: 0,
  host: 1,
  port: 2,
  path: 3,
  query: 4,
  'parent-path': 5,
  filename: 6,
  stem: 7,
  extension: 8
};

const labelsToUriPart: { [key: number]: UriPart } = {
  0: 'scheme',
  1: 'host',
  2: 'port',
  3: 'path',
  4: 'query',
  5: 'parent-path',
  6: 'filename',
  7: 'stem',
  8: 'extension'
};

type MatchType =
  | 'exact-match'
  | 'prefix-match'
  | 'suffix-match'
  | 'contains-match'
  | 'regex-match'
  | 'sha256-match'
  | 'sha512-256-match';

const matchToLabels: { [key: string]: number } = {
  'exact-match': 0,
  'prefix-match': 1,
  'suffix-match': 2,
  'contains-match': 3,
  'regex-match': 4,
  'sha256-match': -1,
  'sha512-256-match': -2
};

const labelsToMatch: { [key: number]: MatchType } = {
  0: 'exact-match',
  1: 'prefix-match',
  2: 'suffix-match',
  3: 'contains-match',
  4: 'regex-match',
  '-1': 'sha256-match',
  '-2': 'sha512-256-match'
};

type UriPartMap = Map<number, string | string[]>;
export type CommonAccessTokenUriMap = Map<number, UriPartMap>;

export class CommonAccessTokenUri {
  private catuMap: CommonAccessTokenUriMap = new Map();

  public static fromDict(dict: { [key: string]: any }) {
    const catu = new CommonAccessTokenUri();
    for (const uriPart in dict) {
      const matchMap = new Map();
      for (const match in dict[uriPart]) {
        matchMap.set(matchToLabels[match], dict[uriPart][match]);
      }
      catu.catuMap.set(uriPartToLabels[uriPart], matchMap);
    }
    return catu;
  }

  public static fromMap(map: CommonAccessTokenUriMap) {
    const catu = new CommonAccessTokenUri();
    catu.catuMap = map;
    return catu;
  }

  private async doMatch(
    value: string,
    matchType: MatchType,
    matchValue: string | string[]
  ) {
    switch (matchType) {
      case 'exact-match':
        if (Array.isArray(matchValue)) {
          throw new InvalidCatuError('Exact match cannot be an array');
        }
        return value === matchValue;
      case 'prefix-match':
        if (Array.isArray(matchValue)) {
          throw new InvalidCatuError('Prefix match cannot be an array');
        }
        return value.startsWith(matchValue);
      case 'suffix-match':
        if (Array.isArray(matchValue)) {
          throw new InvalidCatuError('Suffix match cannot be an array');
        }
        return value.endsWith(matchValue);
      case 'contains-match':
        if (Array.isArray(matchValue)) {
          throw new InvalidCatuError('Contains match cannot be an array');
        }
        return value.includes(matchValue);
      case 'regex-match': {
        if (!Array.isArray(matchValue)) {
          throw new InvalidCatuError('Regex match must be an array');
        }
        const regex = new RegExp(matchValue[0], matchValue[1]);
        return regex.test(value);
      }
      case 'sha256-match': {
        if (Array.isArray(matchValue)) {
          throw new InvalidCatuError('SHA256 match cannot be an array');
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
          throw new InvalidCatuError('SHA512-256 match cannot be an array');
        }
        const encoded512 = await crypto.subtle.digest(
          'SHA-512',
          new TextEncoder().encode(value)
        );
        const encHex512 = base16.encode(new Uint8Array(encoded512));
        return encHex512 === matchValue;
      }
      default:
        throw new InvalidCatuError(`Unsupported match type: ${matchType}`);
    }
  }

  public async match(uri: URL): Promise<boolean> {
    for (const [uriPart, uriPartMap] of this.catuMap) {
      const uriPartType = labelsToUriPart[uriPart];
      const matchLabel = uriPartMap.keys().next().value;
      const matchValue = uriPartMap.get(matchLabel!);
      let value;
      switch (uriPartType) {
        case 'scheme':
          value = uri.protocol.slice(0, -1);
          break;
        case 'host':
          value = uri.hostname;
          break;
        case 'port':
          value = uri.port;
          break;
        case 'path':
          value = uri.pathname;
          break;
        case 'query':
          {
            const params = new URLSearchParams(uri.search);
            params.delete('cat');
            value = params.toString();
          }
          break;
        case 'parent-path':
          {
            const idx = uri.pathname.lastIndexOf('/');
            value = uri.pathname.slice(0, idx);
          }
          break;
        case 'filename':
          {
            const idx = uri.pathname.lastIndexOf('/');
            value = uri.pathname.slice(idx + 1);
          }
          break;
        case 'stem':
          {
            const filename = uri.pathname.split('/').pop();
            value = filename?.slice(
              0,
              filename.indexOf('.') === -1
                ? filename.length
                : filename.indexOf('.')
            );
          }
          break;
        case 'extension':
          {
            const filename = uri.pathname.split('/').pop();
            value = filename?.slice(
              filename.indexOf('.') === -1
                ? filename.length
                : filename.indexOf('.')
            );
          }
          break;
        default:
          throw new InvalidCatuError(`Unsupported URI part: ${uriPartType}`);
      }
      if (
        !(await this.doMatch(value!, labelsToMatch[matchLabel!], matchValue!))
      ) {
        return false;
      }
    }
    return true;
  }

  toDict() {
    const result: { [key: string]: any } = {};
    this.catuMap.forEach((uriPartMap, uriPart) => {
      const part = labelsToUriPart[uriPart];
      const match: { [key: string]: any } = {};
      uriPartMap.forEach((value, matchType) => {
        match[labelsToMatch[matchType]] = value;
      });
      result[part] = match;
    });
    return result;
  }

  get payload() {
    return this.catuMap;
  }
}
