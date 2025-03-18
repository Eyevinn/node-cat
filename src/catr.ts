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

  public static fromDict(dict: { [key: string]: any }) {
    const catr = new CommonAccessTokenRenewal();
    for (const catrPart in dict) {
      catr.catrMap.set(catrPartToLabel[catrPart], dict[catrPart]);
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
      result[labelsToCatrPart[key]] = value;
    }
    return result;
  }

  get renewalType(): CatrRenewalType {
    const type = this.catrMap.get(catrPartToLabel['type']);
    return labelsToCatrRenewalType[type as number];
  }

  get payload() {
    return this.catrMap;
  }
}
