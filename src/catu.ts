import { InvalidCatuError } from './errors';
import {
  labelsToMatch,
  match,
  matchToLabels,
  MatchType,
  MatchValue
} from './cattypes/match';

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

type UriPartMap = Map<number, string | string[]>;
export type CommonAccessTokenUriMap = Map<number, UriPartMap>;

export class CommonAccessTokenUri {
  private catuMap: CommonAccessTokenUriMap = new Map();

  public static fromDict(dict: { [key: string]: any }) {
    const catu = new CommonAccessTokenUri();
    for (const uriPart in dict) {
      const matchMap = new Map<number, MatchValue>();
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
    try {
      return await match(value, matchType, matchValue);
    } catch (err) {
      throw new InvalidCatuError((err as Error).message);
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
