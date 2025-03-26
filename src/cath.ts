import {
  labelsToMatch,
  MatchMap,
  matchToLabels,
  MatchValue
} from './cattypes/match';

export type CommonAccessTokenHeaderMap = Map<string, MatchMap>;

export class CommonAccessTokenHeader {
  private cathMap: CommonAccessTokenHeaderMap = new Map();

  public static fromDictTags(dict: { [key: number]: any }) {
    const newDict: { [key: string]: any } = {};
    for (const headerTag in dict) {
      const matchDict: { [key: string]: any } = {};
      for (const matchTag in dict[headerTag]) {
        const tag = parseInt(matchTag);
        matchDict[labelsToMatch[tag]] = dict[headerTag][matchTag];
      }
      newDict[labelsToMatch[parseInt(headerTag)]] = matchDict;
    }
    return CommonAccessTokenHeader.fromDict(newDict);
  }

  public static fromDict(dict: { [key: string]: any }) {
    const cath = new CommonAccessTokenHeader();
    for (const header in dict) {
      const matchMap = new Map<number, MatchValue>();
      for (const match in dict[header]) {
        matchMap.set(matchToLabels[match], dict[header][match]);
      }
      cath.cathMap.set(header, matchMap);
    }
    return cath;
  }

  public static fromMap(map: CommonAccessTokenHeaderMap) {
    const cath = new CommonAccessTokenHeader();
    cath.cathMap = map;
    return cath;
  }

  toDict() {
    const result: { [key: string]: any } = {};
    this.cathMap.forEach((matchMap, header) => {
      const match: { [key: string]: any } = {};
      matchMap.forEach((value, matchType) => {
        match[labelsToMatch[matchType]] = value;
      });
      result[header] = match;
    });
    return result;
  }

  get payload() {
    return this.cathMap;
  }
}
