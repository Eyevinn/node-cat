
import { CAT } from '.';
import { CommonAccessTokenNetworkIP, ipToNumber, normalizeIPv6Address } from './catnip';
import { IPv4, IPv6 } from 'ipaddr.js';
import { Tag } from 'cbor-x';

const ipAddressAndPrefix = [
  '192.168.1.10',
  '192.168.1.0/24',
  4321,
  1234,
  '192.168.0.0/24',
  '192.168.0.1',
  '2001:0db8:f3c2:156a:e391:7ba4:970f:12bf',
  '2001:db8:0:2000:0:0:0:0/56'
];

describe('Common Access Token Network IP', () => {
  test('Can generate token with catnip claim from json and validate it', async () => {  
    const cat = new CAT({
      expectCwtTag: true,
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
  
    const json = {
      iss: 'eyevinn',
      catv: 1,
      catnip: ipAddressAndPrefix, 
    };
  
    const base64encoded = await cat.generateFromJson(
      json,
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );

    const result = await cat.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn'    
    });
  
    json.catnip = json.catnip.map((catnipObject) => (typeof catnipObject !== 'number') && IPv6.isIPv6(catnipObject) ? normalizeIPv6Address(catnipObject) : catnipObject);
    expect(result.cat?.claims).toEqual(json);
  });

  test('can be constructed from an array and can match', async () => {
    const catnip = CommonAccessTokenNetworkIP.createCatnipFromArray(ipAddressAndPrefix);
    expect(catnip).toBeDefined();
    expect(catnip.payload.length).toEqual(8);    

    expect(catnip.ipMatch('192.168.1.10')).toBeTruthy();
    expect(catnip.ipMatch('192.168.1.11')).toBeTruthy();
    expect(catnip.ipMatch('192.168.0.10')).toBeTruthy();
    expect(catnip.ipMatch('192.168.0.1')).toBeTruthy();
    expect(catnip.ipMatch('2001:0db8:f3c2:156a:e391:7ba4:970f:12bf')).toBeTruthy();
    expect(catnip.ipMatch('2001:db8:0:2000:0:0:0:1')).toBeTruthy();    

    expect(catnip.ipMatch('192.168.5.5')).toBeFalsy();
    expect(catnip.ipMatch('2001:db9:0:2000:0:0:0:1')).toBeFalsy();
    expect(catnip.ipMatch('2001:0db8:f3c2:156a:e391:7ba4:970f:ffff')).toBeFalsy();
  })

  test('can reverse tags to array', async () => {
    const arrayOf = [
      12345,
      new Tag(ipToNumber(IPv4.parse("192.168.0.1")),52),
      new Tag(ipToNumber(IPv6.parse("2001:db8:f3c2:156a:e391:7ba4:970f:12bf")),54),
      new Tag([24,ipToNumber(IPv4.parseCIDR("192.168.0.0/24")[0])],52),
      new Tag([56,ipToNumber(IPv6.parseCIDR("2001:db8:0:2000:0:0:0:0/56")[0])],54)
    ];

    const output = CommonAccessTokenNetworkIP.readCatnipClaimsFromTags(arrayOf);
    expect(output[0]).toBe(12345);
    expect(output[1]).toBe("192.168.0.1");
    expect(output[2]).toBe("2001:db8:f3c2:156a:e391:7ba4:970f:12bf");
    expect(output[3]).toBe("192.168.0.0/24");
    expect(output[4]).toBe("2001:db8:0:2000:0:0:0:0/56");
  })
})
