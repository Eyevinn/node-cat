import { claimsToLabels, CommonAccessTokenDict, labelsToClaim } from './cat';
import { CommonAccessTokenUri } from './catu';

type CatIfValue = Map<number, [number, { [key: string]: string }]>;
export type CommonAccessTokenIfMap = Map<number, CatIfValue>;

export type CatIfDictValue = {
  [key: string]: [
    number,
    { [header: string]: string | [string, CommonAccessTokenDict] },
    string?
  ];
};

const valueToDict: { [key: string]: (value: any) => any } = {
  exp: (value) => {
    const [code, headers, kid] = value;
    const dictHeaders: { [h: string]: any } = {};
    headers.forEach((v: any, header: string) => {
      dictHeaders[header] = valueToDict[header.toLowerCase()]
        ? valueToDict[header.toLowerCase()](v)
        : v;
    });
    return [code, dictHeaders, kid];
  },
  location: (value) => {
    if (typeof value === 'string') {
      return value;
    } else {
      const [url, map] = value;
      const obj: { [key: string]: any } = {};
      (map as Map<string, any>).forEach((v, claim) => {
        const label = parseInt(claim);
        obj[labelsToClaim[label]] = valueToDict[labelsToClaim[label]]
          ? valueToDict[labelsToClaim[label]](v)
          : v;
      });
      return [url, obj];
    }
  },
  catu: (value) => CommonAccessTokenUri.fromMap(value).toDict()
};

const dictToValue: { [key: string]: (value: any) => any } = {
  exp: (value) => {
    const [code, headers, kid] = value;
    const map = new Map<string, any>();
    for (const header in headers) {
      map.set(
        header,
        dictToValue[header.toLowerCase()]
          ? dictToValue[header.toLowerCase()](headers[header])
          : headers[header]
      );
    }
    return [code, map, kid];
  },
  location: (value) => {
    if (typeof value === 'string') {
      return value;
    } else {
      const [url, dict] = value;
      const lmap = new Map<number, any>();
      for (const key in dict) {
        lmap.set(
          claimsToLabels[key],
          dictToValue[key] ? dictToValue[key](dict[key]) : dict[key]
        );
      }
      return [url, lmap];
    }
  },
  catu: (value) => CommonAccessTokenUri.fromDict(value).payload
};

export class CommonAccessTokenIf {
  private catIfMap: CommonAccessTokenIfMap = new Map();

  /**
   * Create a CATIF claim from a dictionary with numbers as keys (labels)
   */
  public static fromDictTags(dict: { [key: number]: any }) {
    const newDict: { [key: string]: any } = {};
    for (const key in dict) {
      const tag = parseInt(key);
      newDict[labelsToClaim[tag]] = dict[key];
    }
    return CommonAccessTokenIf.fromDict(newDict);
  }

  /**
   * Create a CATIF claim from a dictionary with string as keys
   */
  public static fromDict(dict: { [key: string]: any }) {
    const catif = new CommonAccessTokenIf();
    for (const catIfClaim in dict) {
      const v = dict[catIfClaim];
      catif.catIfMap.set(
        claimsToLabels[catIfClaim],
        dictToValue[catIfClaim] ? dictToValue[catIfClaim](v) : v
      );
    }
    return catif;
  }

  /**
   * Create a CATIF claim from a map with string as keys
   */
  public static fromMap(map: CommonAccessTokenIfMap) {
    const catif = new CommonAccessTokenIf();
    catif.catIfMap = map;
    return catif;
  }

  toDict() {
    const result: { [key: string]: any } = {};
    this.catIfMap.forEach((catIfValue, claim) => {
      result[labelsToClaim[claim]] =
        valueToDict[labelsToClaim[claim]](catIfValue);
    });
    return result;
  }

  get payload() {
    return this.catIfMap;
  }
}
