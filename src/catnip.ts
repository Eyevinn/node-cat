

import { Tag } from "cbor-x";
import ipaddr, { IPv4, IPv6, parse } from "ipaddr.js";

const CatnipIPVersionToLabel: { [key: string]: number} = {
    IPv4: 52,
    IPv6: 54
}

const CatnipLabelToIPVersion: { [key: number]: string } = {
    52: "ipv4",
    54: "ipv6"
}

//type CatnipPartValue = number | 
//type CatnipPartMap = Map<number, 

/*
export type PrefixPart = Array<number | Buffer>;
export type IPPrefix = Map<number, PrefixPart>;
export type IPAddress = Map<number, number | Buffer>;
export type ASN = number;
*/ 

//type CatnipObject = ASN | IPAddress | IPPrefix;

//export type CommonAccessTokenNetworkIPArray = Array<ASN | IPAddress | IPPrefix | Tag>;
export type CommonAccessTokenNetworkIPArray = Array<number | Tag>; 

export function isASN(value: string | number) {
    const asn = typeof value === 'string' ? parseInt(value) : value;
    return !Number.isNaN(asn) && (
    (asn >= 1 && asn <= 65434) ||
    (asn >= 131072 && asn <= 4294967294) 
    )
}

export function ipToNumber(ip : IPv4| IPv6) {
    return Buffer.from(Uint8Array.from(ip.toByteArray()));
}

export class CommonAccessTokenNetworkIP {
    private catnipArray: CommonAccessTokenNetworkIPArray = new Array();

    /**
     * Create catnip claim string array from array of catnip tags, and number
     */
    public static readCatnipClaimsFromTags(arrayOfASNOrIPorIPPrefix: Array<number | Tag>) : Array<any> {
        const catnipClaims = new Array<any>;
        for (let catnipObject of arrayOfASNOrIPorIPPrefix) {
            if (typeof catnipObject === 'number') {
                catnipClaims.push(catnipObject);
            } else if (catnipObject instanceof Tag) {
                const value = catnipObject.value;
                if (catnipObject.tag == CatnipIPVersionToLabel.IPv4) {
                    if (value instanceof Array) {
                        const [cidr, ipv4Buffer] = catnipObject.value;
                        const ip = ipaddr.fromByteArray(ipv4Buffer)
                        catnipClaims.push(`${ip.toString()}/${cidr}`)
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
    public static createCatnipFromArray(catnipObjectsAsStringOrNumber: Array<number | string>) : CommonAccessTokenNetworkIP {
        const catnip = new CommonAccessTokenNetworkIP();
        const catnipParsed = catnipObjectsAsStringOrNumber.map((x) => {return typeof x === 'number' ? x.toString() : x;});
        for (let catnipString of catnipParsed) {
            if (!catnipString.includes(".") &&
                !catnipString.includes(":") && 
                isASN(catnipString)) {
                catnip.catnipArray.push(Number.parseInt(catnipString));
            } else if (IPv4.isValid(catnipString)) {
                const ip = IPv4.parse(catnipString);
                catnip.catnipArray.push(new Tag(ipToNumber(ip),52));
           } else if (IPv4.isValidCIDR(catnipString)) {
                const [ip, cidr] = IPv4.parseCIDR(catnipString);
                catnip.catnipArray.push(new Tag([cidr, ipToNumber(ip)], 52));
           } else if (IPv6.isValid(catnipString)) {
                const ip = IPv6.parse(catnipString);
                catnip.catnipArray.push(new Tag(ipToNumber(ip), 54))
           } else if (IPv6.isValidCIDR(catnipString)) {
                const [ip, cidr] = IPv6.parseCIDR(catnipString);
                catnip.catnipArray.push(new Tag([cidr,ipToNumber(ip)], 54));
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
        return CommonAccessTokenNetworkIP.readCatnipClaimsFromTags(this.catnipArray);
    }

    get payload() {
        return this.catnipArray;
    }
}


