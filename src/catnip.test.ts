
import { CAT } from '.';
import {CommonAccessTokenUri } from './catu';
import { CommonAccessToken, CommonAccessTokenFactory } from './cat';
import { CommonAccessTokenNetworkIP, ipToNumber } from './catnip';
import ipaddr, { IPv4, IPv6 } from 'ipaddr.js';
import { Encoder, Decoder, Tag } from 'cbor-x';

/*

test('generate token with catnip claim from dict', async () => {
  const ipAddressAndPrefix = [
    '192.168.1.10',
    '192.168.1.0/24',
    '4321',
    1234,
    '192.168.1.0/24',
    '192.168.0.0/24',
    '192.168.0.1',
    '2001:0db8:f3c2:156a:e391:7ba4:970f:12bf',
    '2001:db8:0:2000::/56',
    '2001:0db8:0000:2000:0000:0000:0000:0000/56'
  ];

  const generator = new CAT({
    expectCwtTag: true,
    keys: {
      Symmetric256: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      )
    }
  });
  
  const base64encoded = await generator.generate(
    {
      iss: 'eyevinn',
      catnip: CommonAccessTokenNetworkIP.createCatnipFromArray(ipAddressAndPrefix).payload, 
    },
    {
      type: 'mac',
      alg: 'HS256',
      kid: 'Symmetric256'
    }
  );
  console.log(base64encoded);

});
*/

test('generate token with catnip claim from json', async () => {
  const ipAddressAndPrefix = [
    '192.168.1.10',
    '192.168.1.0/24',
    4321,
    1234,
    '192.168.1.0/24',
    '192.168.0.0/24',
    '192.168.0.1',
    '2001:0db8:f3c2:156a:e391:7ba4:970f:12bf',
    '2001:db8:0:2000:0:0:0:0/56'
  ];

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
    catu: {
      scheme: {
        'exact-match': 'https'
      }
    }
  };

  const base64encoded = await cat.generateFromJson(
    json,
    {
      type: 'mac',
      alg: 'HS256',
      kid: 'Symmetric256'
    }
  );
  console.log(base64encoded);

  const result = await cat.validate(base64encoded!, 'mac', {
    issuer: 'eyevinn'
  });

  json.catnip = json.catnip.map((x) => (typeof x !== 'number') && IPv6.isIPv6(x) ? normalizeIPAddress(x) : x);
  
  
  expect(result.cat?.claims).toEqual(json);
});

function normalizeIPAddress(x: string) {
  if (IPv6.isValid(x)) {
    return IPv6.parse(x).toNormalizedString();
  } else if (IPv6.isValidCIDR(x)) {
    const [ip, cidr ] = IPv6.parseCIDR(x);
    return `${ip.toNormalizedString()}/${cidr}`;
  }
  throw new Error("x");
}


/*
describe('Common Access Token IP', () => {
    test('can be constructed from a list',async () => {
      const CWT_TAG = 61;

      
      const encoder = new Encoder({
        mapsAsObjects: false,
        useRecords: false
      });

      const decoder = new Decoder({
        mapsAsObjects: false,
        useRecords: false
      });
      
      const alg = 'HS256';
      const key = {
        k: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        ),
        kid: 'Symmetric256'
      };

      const headers = {
        p: { alg: alg },
        u: { kid: key.kid }
      };
      const recipient = {
        key: key.k
      };

      const ipAddressAndPrefix = [
        '192.168.1.10',
        '192.168.1.0/24',
        '4321',
        1234,
        '192.168.1.0/24',
        '192.168.0.0/24',
        '192.168.0.1',
        '2001:0db8:f3c2:156a:e391:7ba4:970f:12bf',
        '2001:db8:0:2000::/56',
        '2001:0db8:0000:2000:0000:0000:0000:0000/56'
      ];

    const catnip = CommonAccessTokenNetworkIP.createCatnipFromArray(ipAddressAndPrefix);
    const data = encoder.encode(catnip.payload);
    const token = data.toString('hex');
    console.log(token);

    const decodedData = decoder.decode(data);
    const catnip2 = CommonAccessTokenNetworkIP.readCatnipClaimsFromTags(catnip.payload);
  })
})

describe('test ipaddr.js', () =>  {
  test('test ipToNumber', () => {
    const ipInt = ipToNumber(IPv4.parse("192.168.0.1"));
    console.log(ipInt);
    
  })
})

test('can generate a token from JSON with all claims and verify it', async () => {
  const generator = new CAT({
    keys: {
      Symmetric256: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      )
    }
  });
  const json = {
    catv: 1,
    catnip: ['192.168.1.10']
  };
  const base64encoded = await generator.generateFromJson(json, {
    type: 'mac',
    alg: 'HS256',
    kid: 'Symmetric256'
  });

  const validator = new CAT({
    keys: {
      Symmetric256: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      )
    }
  });
  
  const result = await validator.validate(base64encoded!, 'mac', {
    issuer: 'coap://as.example.com'
  });

  expect(result.cat?.claims).toEqual(json);
});

*/

