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
    return [code, valueToDict['location'](headers.get('Location')), kid];
  },
  location: (value) => {
    if (typeof value === 'string') {
      return { Location: value };
    } else {
      const [url, map] = value;
      const obj: { [key: string]: any } = {};
      (map as Map<string, any>).forEach((v, claim) => {
        obj[claim] = valueToDict[claim] ? valueToDict[claim](v) : v;
      });
      return { Location: [url, obj] };
    }
  },
  catu: (value) => CommonAccessTokenUri.fromUnlabeledMap(value).toDict()
};

const dictToValue: { [key: string]: (value: any) => any } = {
  exp: (value) => {
    const [code, headers, kid] = value;
    return [code, dictToValue['location'](headers['Location']), kid];
  },
  location: (value) => {
    if (typeof value === 'string') {
      const map = new Map<string, any>();
      map.set('Location', value);
      return map;
    } else {
      const [url, dict] = value;
      const lmap = new Map<string, any>();
      for (const key in dict) {
        lmap.set(
          key,
          dictToValue[key] ? dictToValue[key](dict[key]) : dict[key]
        );
      }
      const map = new Map<string, any>();
      map.set('Location', [url, lmap]);
      return map;
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
