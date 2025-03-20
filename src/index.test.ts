import { CAT } from '.';
import { CommonAccessTokenRenewal } from './catr';
import { CommonAccessTokenUri } from './catu';
import {
  InvalidAudienceError,
  InvalidIssuerError,
  KeyNotFoundError,
  TokenExpiredError,
  TokenNotActiveError,
  UriNotAllowedError
} from './errors';

describe('CAT', () => {
  test('can generate a token and verify it', async () => {
    const generator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
    const base64encoded = await generator.generate(
      {
        iss: 'coap://as.example.com'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );
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
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
    expect(result.cat!.claims).toEqual({
      iss: 'coap://as.example.com',
      catv: 1
    });
  });

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
      iss: 'coap://as.example.com',
      aud: ['one', 'two'],
      exp: Math.floor(Date.now() / 1000) + 60,
      nbf: Math.floor(Date.now() / 1000) - 60,
      cti: 'a47019af6305d3652a918ae356cc2ca2',
      catreplay: 0,
      catpor: ['.00005', '087ee44f239f7a2e34b3d1649aad8c1d', 1700000000],
      catv: 1,
      catnip: [],
      catu: {
        scheme: {
          'exact-match': 'https'
        }
      },
      catm: ['GET'],
      cath: {
        'User-Agent': {
          contains: 'Mozilla'
        }
      },
      catgeoiso3166: ['SE'],
      catgeocoord: [],
      geohash: [],
      cattpk: 'a47019af6305d3652a918ae356cc2ca2',
      sub: 'jonas',
      iat: Math.floor(Date.now() / 1000),
      catifdata: ['catif'],
      catif: {
        exp: [
          307,
          {
            Location: 'https://auth.example.net'
          }
        ]
      },
      catr: {
        type: 'header',
        'header-name': 'cta-common-access-token',
        expadd: 120,
        deadline: 60
      }
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

  test('can generate a token from a JSON object and verify it', async () => {
    const generator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
    const base64encoded = await generator.generateFromJson(
      {
        iss: 'coap://as.example.com',
        exp: Math.floor(Date.now() / 1000) + 60,
        catr: {
          type: 'header',
          'header-name': 'cta-common-access-token',
          expadd: 120,
          deadline: 60
        },
        catu: {
          scheme: {
            'exact-match': 'https'
          }
        }
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
    const result = await validator.validate(base64encoded!, 'mac', {
      issuer: 'coap://as.example.com',
      url: new URL('https://example.com')
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
    expect(result.cat!.claims).toEqual({
      iss: 'coap://as.example.com',
      catr: {
        deadline: 60,
        expadd: 120,
        'header-name': 'cta-common-access-token',
        type: 'header'
      },
      catu: {
        scheme: {
          'exact-match': 'https'
        }
      },
      exp: expect.any(Number),
      catv: 1
    });
  });

  test('can validate a MAC:ed token with standard claims', async () => {
    const base64encoded =
      '0YRDoQEFoQRMU3ltbWV0cmljMjU2eDZkOTAxMDNhMTAxNzU2MzZmNjE3MDNhMmYyZjYxNzMyZTY1Nzg2MTZkNzA2YzY1MmU2MzZmNmRYIDL8dIteq8pMXXX9oL4eo2NX1kQUaselV6p/JHSEVXWX';
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
    const result = await validator.validate(base64encoded, 'mac', {
      issuer: 'coap://as.example.com'
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
    expect(result.cat!.claims).toEqual({
      iss: 'coap://as.example.com'
    });
  });

  test('can validate a MAC:ed token with CWT tag', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2WCijAXgYY29hcDovL2pvbmFzLmV4YW1wbGUuY29tBhpn1JipBRpn1JipWCCX4nQb8SYQoa0SFLxE2Rh35DdTjoA9TzOSy1IP9O1BGQ';
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });
    const result = await validator.validate(base64encoded, 'mac', {
      issuer: 'coap://jonas.example.com'
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
    expect(result.cat!.claims).toEqual({
      iss: 'coap://jonas.example.com',
      iat: 1741985961,
      nbf: 1741985961
    });
  });

  test('can handle multiple keys (under rotation)', async () => {
    const validator = new CAT({
      keys: {
        keyone: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        ),
        keytwo: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569389',
          'hex'
        )
      },
      expectCwtTag: true
    });

    const generator1 = new CAT({
      keys: {
        keyone: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });
    const token1 = await generator1.generate(
      {
        iss: 'coap://as.example.com'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'keyone'
      }
    );
    const cat = await validator.validate(token1!, 'mac', {
      issuer: 'coap://as.example.com'
    });
    expect(cat).toBeDefined();

    const generator2 = new CAT({
      keys: {
        keythree: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569398',
          'hex'
        )
      },
      expectCwtTag: true
    });
    const token2 = await generator2.generate(
      {
        iss: 'coap://as.example.com'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'keythree'
      }
    );
    await expect(
      validator.validate(token2!, 'mac', {
        issuer: 'coap://as.example.com'
      })
    ).rejects.toThrow(KeyNotFoundError);
  });
});

describe('CAT claims', () => {
  let validator: CAT;
  let generator: CAT;

  beforeEach(() => {
    validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });
    generator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });
  });

  test('fail if wrong issuer', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2VKMBZWpvbmFzBhpn12U-BRpn12U-WCDf1xHvhcnvyXUxd-DP4RAbayc8nC2PLJPPPbF3S00ruw';
    const result = await validator.validate(base64encoded, 'mac', {
      issuer: 'coap://jonas.example.com'
    });
    expect(result.error).toBeInstanceOf(InvalidIssuerError);
  });

  test('pass if token has not expired', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGnUCOrsGGmfXRKwFGmfXRKxYIOM6yRx830uqAamWFv1amFYRa5vaV2z5lIQTqFEvFh8z';
    const result = await validator.validate(base64encoded, 'mac', {
      issuer: 'eyevinn'
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
  });

  test('fail if token expired', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGmfXP_YGGmfXQAsFGmfXQAtYINTT_KlOyhaV6NaSxFXkqJWfBagSkPkem10dysoA-C0w';

    const result = await validator.validate(base64encoded, 'mac', {
      issuer: 'eyevinn'
    });
    expect(result.error).toBeInstanceOf(TokenExpiredError);
  });

  test('pass if token has a valid audience', async () => {
    // {"aud": ["one", "two"]}
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2V6MDgmNvbmVjdHdvBhpn12R8BRpn12R8WCAdnSbUN4KbIvaHLn-q4f4YRpfq6ERYotByjbIyZ-EkfQ';
    const result = await validator.validate(base64encoded, 'mac', {
      issuer: 'eyevinn',
      audience: ['one', 'three']
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
  });

  test('fail if token has an invalid audience', async () => {
    // {"aud": ["one", "two"]}
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2V6MDgmNvbmVjdHdvBhpn12R8BRpn12R8WCAdnSbUN4KbIvaHLn-q4f4YRpfq6ERYotByjbIyZ-EkfQ';
    const result = await validator.validate(base64encoded, 'mac', {
      issuer: 'eyevinn',
      audience: ['three']
    });
    expect(result.error).toBeInstanceOf(InvalidAudienceError);
  });

  test('fail if token is not active yet', async () => {
    const nbf = Math.floor(Date.now() / 1000) + 1000;
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        nbf
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );
    const result = await validator.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn'
    });
    expect(result.error).toBeInstanceOf(TokenNotActiveError);
  });

  test('pass if token is active', async () => {
    const nbf = Math.floor(Date.now() / 1000) - 1000;
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        nbf
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );
    const result = await validator.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn'
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
  });

  test('pass if token has a catu claim that matches url', async () => {
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        catu: CommonAccessTokenUri.fromDict({
          scheme: {
            'exact-match': 'https'
          },
          path: {
            'prefix-match': '/content'
          },
          extension: {
            'exact-match': '.m3u8'
          }
        }).payload
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );
    const result = await validator.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn',
      url: new URL('https://example.com/content/path/file.m3u8')
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
    const result2 = await validator.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn',
      url: new URL('https://example.com/content/path/file.ts')
    });
    expect(result2.error).toBeInstanceOf(UriNotAllowedError);
  });

  test('can provide CWT Id claim', async () => {
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        cti: 'a47019af6305d3652a918ae356cc2ca2'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );
    const result = await validator.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn'
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
    expect(result.cat!.claims.cti).toEqual('a47019af6305d3652a918ae356cc2ca2');
  });

  test('can auto generate a CWT Id claim', async () => {
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );
    const result = await validator.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn'
    });
    expect(result.error).not.toBeDefined();
    expect(result.cat).toBeDefined();
    expect(result.cat!.cti).toBeDefined();
  });

  test('can renew a token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        exp: now,
        catr: CommonAccessTokenRenewal.fromDict({
          type: 'header',
          'header-name': 'cta-common-access-token',
          expadd: 120,
          deadline: 60
        }).payload
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );
    const result = await validator.validate(base64encoded!, 'mac', {
      issuer: 'eyevinn'
    });
    const renewed = await validator.renewToken(result.cat!, {
      type: 'mac',
      issuer: 'renew',
      kid: 'Symmetric256',
      alg: 'HS256'
    });
    const result2 = await validator.validate(renewed, 'mac', {
      issuer: 'renew'
    });
    expect((result2.cat?.claims.exp as number) - now == 120).toBeTruthy();
  });
});
