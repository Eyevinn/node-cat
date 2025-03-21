import { claimsToLabels, labelsToClaim } from './cat';

type CatIfValue = Map<number, [number, { [key: string]: string }]>;
export type CommonAccessTokenIfMap = Map<number, CatIfValue>;

export class CommonAccessTokenIf {
  private catIfMap: CommonAccessTokenIfMap = new Map();

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
