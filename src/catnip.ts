import { Tag } from 'cbor-x';
import ipaddr, { IPv4, IPv6 } from 'ipaddr.js';

const CatnipIPVersionToLabel: { [key: string]: number } = {
  IPv4: 52,
  IPv6: 54
};

const CatnipLabelToIPVersion: { [key: number]: string } = {
  52: 'ipv4',
  54: 'ipv6'
};

const IPAddressKind: { [key: string]: string } = {
  IPv4: 'ipv4',
  IPv6: 'ipv6'
};

export type ASN = number;
export type CatnipObject = ASN | Tag;
export type CommonAccessTokenNetworkIPArray = Array<CatnipObject>;

export function isASN(value: string | number) {
  const asn = typeof value === 'string' ? parseInt(value) : value;
  return !Number.isNaN(asn) && asn >= 0 && asn <= 0xffffffff;
}

export function ipToNumber(ip: IPv4 | IPv6) {
  return Buffer.from(Uint8Array.from(ip.toByteArray()));
}

export function ipV6AddressToRFC5952String(
  ipv6AddressOrIPPrefix: string
): string {
  if (IPv6.isValid(ipv6AddressOrIPPrefix)) {
    return IPv6.parse(ipv6AddressOrIPPrefix).toRFC5952String();
  } else if (IPv6.isValidCIDR(ipv6AddressOrIPPrefix)) {
    const [ip, cidr] = IPv6.parseCIDR(ipv6AddressOrIPPrefix);
    return `${ip.toRFC5952String()}/${cidr}`;
  }
  throw new Error('Not valid IPv6 address or prefix');
}

export function normalizeIPv6Address(ipv6AddressOrIPPrefix: string): string {
  if (IPv6.isValid(ipv6AddressOrIPPrefix)) {
    return IPv6.parse(ipv6AddressOrIPPrefix).toNormalizedString();
  } else if (IPv6.isValidCIDR(ipv6AddressOrIPPrefix)) {
    const [ip, cidr] = IPv6.parseCIDR(ipv6AddressOrIPPrefix);
    return `${ip.toNormalizedString()}/${cidr}`;
  }
  throw new Error('Not valid IPv6 address or prefix');
}

export class CommonAccessTokenNetworkIP {
  private catnipArray: CommonAccessTokenNetworkIPArray =
    new Array<CatnipObject>();

  /**
   * Create catnip claim string array from array of catnip tags, and number
   */
  public static readCatnipClaimsFromTags(
    arrayOfASNOrIPorIPPrefix: Array<CatnipObject>
  ): Array<number | string> {
    const catnipClaims = new Array<number | string>();
    for (const catnipObject of arrayOfASNOrIPorIPPrefix) {
      if (typeof catnipObject === 'number') {
        catnipClaims.push(catnipObject);
      } else if (catnipObject instanceof Tag) {
        const value = catnipObject.value;
        if (catnipObject.tag == CatnipIPVersionToLabel.IPv4) {
          if (value instanceof Array) {
            const [cidr, ipv4Buffer] = catnipObject.value;
            const ip = ipaddr.fromByteArray(ipv4Buffer);
            catnipClaims.push(`${ip.toString()}/${cidr}`);
          } else if (value instanceof Buffer) {
            const ip = ipaddr.fromByteArray([...value]);
            catnipClaims.push(`${ip.toString()}`);
          }
        } else if (catnipObject.tag == CatnipIPVersionToLabel.IPv6) {
          if (value instanceof Array) {
            const [cidr, ipv6Buffer] = catnipObject.value;
            const ip = ipaddr.fromByteArray(ipv6Buffer);
            catnipClaims.push(`${ip.toNormalizedString()}/${cidr}`);
          } else if (value instanceof Buffer) {
            const ip = ipaddr.fromByteArray([...value]);
            catnipClaims.push(`${ip.toNormalizedString()}`);
          }
        }
      }
    }
    return catnipClaims;
  }

  /**
   * Create a CATNIP claim from a array of (strings or numbers). (asn, IPv4 address, IPv6 address, IPv4 prefix, IPv6 prefix).
   * @param catnip
   * @returns
   */
  public static createCatnipFromArray(
    catnipObjectsAsStringOrNumber: Array<number | string>
  ): CommonAccessTokenNetworkIP {
    const catnip = new CommonAccessTokenNetworkIP();
    const catnipParsed = catnipObjectsAsStringOrNumber.map((x) => {
      return typeof x === 'number' ? x.toString() : x;
    });

    for (const catnipString of catnipParsed) {
      if (
        !catnipString.includes('.') &&
        !catnipString.includes(':') &&
        isASN(catnipString)
      ) {
        catnip.catnipArray.push(Number.parseInt(catnipString));
      } else if (IPv4.isValid(catnipString)) {
        const ip = IPv4.parse(catnipString);
        catnip.catnipArray.push(new Tag(ipToNumber(ip), 52));
      } else if (IPv4.isValidCIDR(catnipString)) {
        const [ip, cidr] = IPv4.parseCIDR(catnipString);
        catnip.catnipArray.push(new Tag([cidr, ipToNumber(ip)], 52));
      } else if (IPv6.isValid(catnipString)) {
        const ip = IPv6.parse(catnipString);
        catnip.catnipArray.push(new Tag(ipToNumber(ip), 54));
      } else if (IPv6.isValidCIDR(catnipString)) {
        const [ip, cidr] = IPv6.parseCIDR(catnipString);
        catnip.catnipArray.push(new Tag([cidr, ipToNumber(ip)], 54));
      }
    }
    return catnip;
  }

  public static fromArray(catnipArray: CommonAccessTokenNetworkIPArray) {
    const catnip = new CommonAccessTokenNetworkIP();
    catnip.catnipArray = catnipArray;
    return catnip;
  }

  toArray() {
    return CommonAccessTokenNetworkIP.readCatnipClaimsFromTags(
      this.catnipArray
    );
  }

  get payload() {
    return this.catnipArray;
  }

  public ipMatch(ip: string): boolean {
    try {
      const ipAddr = ipaddr.parse(ip);
      return this.catnipArray
        .filter((catnipObject) => {
          if (typeof catnipObject === 'number') return false;
          if (!(catnipObject instanceof Tag)) return false;
          return true;
        })
        .map((co) => {
          const catnipObject = co as Tag;
          const value = catnipObject.value;
          if (
            catnipObject.tag == CatnipIPVersionToLabel.IPv4 &&
            ipAddr.kind() === IPAddressKind.IPv4
          ) {
            if (value instanceof Array) {
              const [cidr, ipv4Buffer] = catnipObject.value;
              const ip = ipaddr.fromByteArray(ipv4Buffer);
              return ipAddr.match(ip, cidr);
            } else if (value instanceof Buffer) {
              const ip = ipaddr.fromByteArray([...value]);
              return ipAddr.match(ip, 32);
            }
          } else if (
            catnipObject.tag == CatnipIPVersionToLabel.IPv6 &&
            ipAddr.kind() === IPAddressKind.IPv6
          ) {
            if (value instanceof Array) {
              const [cidr, ipv6Buffer] = catnipObject.value;
              const ip = ipaddr.fromByteArray(ipv6Buffer);
              return ipAddr.match(ip, cidr);
            } else if (value instanceof Buffer) {
              const ip = ipaddr.fromByteArray([...value]);
              return ipAddr.match(ip, 128);
            }
          }
          return false;
        })
        .some((matchingIPorPrefix) => matchingIPorPrefix === true);
    } catch (error: any) {
      return false;
    }
  }

  public asnMatch(asn: number): boolean {
    return this.catnipArray
      .filter((catnipObject) => {
        if (typeof catnipObject === 'number') return true;
        return false;
      })
      .some((catnipObject) => asn === catnipObject);
  }
}
