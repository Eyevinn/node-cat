type CatrPart =
  | 'type'
  | 'expadd'
  | 'deadline'
  | 'cookie-name'
  | 'header-name'
  | 'cookie-params'
  | 'header-params'
  | 'code';

type CatrRenewalType = 'automatic' | 'cookie' | 'header' | 'redirect';

const catrPartToLabel: { [key: string]: number } = {
  type: 0,
  expadd: 1,
  deadline: 2,
  'cookie-name': 3,
  'header-name': 4,
  'cookie-params': 5,
  'header-params': 6,
  code: 7
};

const labelsToCatrPart: { [key: number]: CatrPart } = {
  0: 'type',
  1: 'expadd',
  2: 'deadline',
  3: 'cookie-name',
  4: 'header-name',
  5: 'cookie-params',
  6: 'header-params',
  7: 'code'
};

const catrRenewalTypeToLabel: { [key: string]: number } = {
  automatic: 0,
  cookie: 1,
  header: 2,
  redirect: 3
};
const labelsToCatrRenewalType: { [key: number]: CatrRenewalType } = {
  0: 'automatic',
  1: 'cookie',
  2: 'header',
  3: 'redirect'
};

type CatrPartValue = number | string | string[];
export type CommonAccessTokenRenewalMap = Map<number, CatrPartValue>;

export class CommonAccessTokenRenewal {
  private catrMap: CommonAccessTokenRenewalMap = new Map();

  public static fromDictTags(dict: { [key: number]: any }) {
    const newDict: { [key: string]: any } = {};
    for (const key in dict) {
      const tag = parseInt(key);
      if (labelsToCatrPart[tag] === 'type') {
        newDict[labelsToCatrPart[tag]] = labelsToCatrRenewalType[dict[key]];
      } else {
        newDict[labelsToCatrPart[tag]] = dict[key];
      }
    }
    return CommonAccessTokenRenewal.fromDict(newDict);
  }

  public static fromDict(dict: { [key: string]: any }) {
    const catr = new CommonAccessTokenRenewal();
    for (const catrPart in dict) {
      if (catrPart === 'type') {
        catr.catrMap.set(
          catrPartToLabel[catrPart],
          catrRenewalTypeToLabel[dict[catrPart]]
        );
      } else {
        catr.catrMap.set(catrPartToLabel[catrPart], dict[catrPart]);
      }
    }
    return catr;
  }

  public static fromMap(map: CommonAccessTokenRenewalMap) {
    const catr = new CommonAccessTokenRenewal();
    catr.catrMap = map;
    return catr;
  }

  toDict() {
    const result: { [key: string]: any } = {};
    for (const [key, value] of this.catrMap.entries()) {
      if (labelsToCatrPart[key] === 'type') {
        result[labelsToCatrPart[key]] =
          labelsToCatrRenewalType[value as number];
      } else {
        result[labelsToCatrPart[key]] = value;
      }
    }
    return result;
  }

  isValid() {
    if (this.catrMap.get(catrPartToLabel['type']) === undefined) {
      return false;
    }
    if (this.catrMap.get(catrPartToLabel['expadd']) === undefined) {
      return false;
    }
    return true;
  }

  get renewalType(): CatrRenewalType {
    const type = this.catrMap.get(catrPartToLabel['type']);
    return labelsToCatrRenewalType[type as number];
  }

  get payload() {
    return this.catrMap;
  }
}
