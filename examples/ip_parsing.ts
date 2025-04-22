


import ipaddr, { IPv4, IPv6 } from 'ipaddr.js'

import { CommonAccessTokenNetworkIP } from '../src/catnip'


import * as cbor from 'cbor-x';


const ipAddressAndPrefix = [
    '192.168.1.10',
    '192.168.1.0/24',
    4321,
    1234,
    '192.168.1.0/24',
    '192.168.0.0/24',
    '192.168.0.1',
    '2001:0db8:f3c2:156a:e391:7ba4:970f:12bf',
    '2001:db8:0:2000::/56',
    '2001:0db8:0000:2000:0000:0000:0000:0000/56'
  ];

const x = ipaddr.isValid("2001:db8:0:2000::");

console.log(x);




/*

export function ipToNumber(ip : IPv4| IPv6) {
    return Buffer.from(Uint8Array.from(ip.toByteArray()));
}

const map = new Map();


const ipMap = new Map()

ipMap.set(52, ipToNumber(ipaddr.parse("192.168.0.1")));
map.set(311,[ipMap])
const encoder = new cbor.Encoder({useRecords: false, mapsAsObjects: false});
console.log(encoder.encode(map).toString('hex'));



*/



/*

const catnip = new CommonAccessTokenNetworkIP();

const x = CommonAccessTokenNetworkIP.fromArray(["192.168.0.1"]);
let ip = ipaddr.parse("192.168.0.1/24");
ip = ipaddr.parse("x");
let cidr = ipaddr.parseCIDR("192.168.0.1/24")






console.log(ip);

*/
