import { claimsToLabels, CommonAccessTokenDict, labelsToClaim } from './cat';

type CatIfValue = Map<number, [number, { [key: string]: string }]>;
export type CommonAccessTokenIfMap = Map<number, CatIfValue>;

export type CatIfDictValue = {
  [key: string]: [
    number,
    { [header: string]: string | [string, CommonAccessTokenDict] },
    string?
  ];
};

export class CommonAccessTokenIf {
  private catIfMap: CommonAccessTokenIfMap = new Map();

  public static fromDictTags(dict: { [key: number]: any }) {
    const newDict: { [key: string]: any } = {};
    for (const key in dict) {
      const tag = parseInt(key);
      newDict[labelsToClaim[tag]] = dict[key];
    }
    return CommonAccessTokenIf.fromDict(newDict);
  }

  public static fromDict(dict: { [key: string]: any }) {
    const catif = new CommonAccessTokenIf();
    for (const catIfClaim in dict) {
      catif.catIfMap.set(claimsToLabels[catIfClaim], dict[catIfClaim]);
    }
    return catif;
  }

  public static fromMap(map: CommonAccessTokenIfMap) {
    const catif = new CommonAccessTokenIf();
    catif.catIfMap = map;
    return catif;
  }

  toDict() {
    const result: { [key: string]: any } = {};
    this.catIfMap.forEach((catIfValue, claim) => {
      result[labelsToClaim[claim]] = catIfValue;
    });
    return result;
  }

  get payload() {
    return this.catIfMap;
  }
}
