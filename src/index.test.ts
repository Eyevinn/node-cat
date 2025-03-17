import { CAT } from '.';
import {
  InvalidAudienceError,
  InvalidIssuerError,
  TokenExpiredError
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
    const cat = await validator.validate(base64encoded!, 'mac', {
      kid: 'Symmetric256',
      issuer: 'coap://as.example.com'
    });
    expect(cat).toBeDefined();
    expect(cat!.claims).toEqual({
      iss: 'coap://as.example.com'
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
    const cat = await validator.validate(base64encoded, 'mac', {
      kid: 'Symmetric256',
      issuer: 'coap://as.example.com'
    });
    expect(cat).toBeDefined();
    expect(cat!.claims).toEqual({
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
    const cat = await validator.validate(base64encoded, 'mac', {
      kid: 'Symmetric256',
      issuer: 'coap://jonas.example.com'
    });
    expect(cat).toBeDefined();
    expect(cat!.claims).toEqual({
      iss: 'coap://jonas.example.com',
      iat: 1741985961,
      nbf: 1741985961
    });
  });
});

describe('CAT claims', () => {
  let validator: CAT;

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
  });

  test('fail if wrong issuer', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2VKMBZWpvbmFzBhpn12U-BRpn12U-WCDf1xHvhcnvyXUxd-DP4RAbayc8nC2PLJPPPbF3S00ruw';
    await expect(
      validator.validate(base64encoded, 'mac', {
        kid: 'Symmetric256',
        issuer: 'coap://jonas.example.com'
      })
    ).rejects.toThrow(InvalidIssuerError);
  });

  test('pass if token has not expired', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGnUCOrsGGmfXRKwFGmfXRKxYIOM6yRx830uqAamWFv1amFYRa5vaV2z5lIQTqFEvFh8z';
    const cat = validator.validate(base64encoded, 'mac', {
      kid: 'Symmetric256',
      issuer: 'eyevinn'
    });
    expect(cat).toBeDefined();
  });

  test('fail if token expired', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGmfXP_YGGmfXQAsFGmfXQAtYINTT_KlOyhaV6NaSxFXkqJWfBagSkPkem10dysoA-C0w';
    await expect(
      validator.validate(base64encoded, 'mac', {
        kid: 'Symmetric256',
        issuer: 'eyevinn'
      })
    ).rejects.toThrow(TokenExpiredError);
  });

  test('pass if token has a valid audience', async () => {
    // {"aud": ["one", "two"]}
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2V6MDgmNvbmVjdHdvBhpn12R8BRpn12R8WCAdnSbUN4KbIvaHLn-q4f4YRpfq6ERYotByjbIyZ-EkfQ';
    const cat = validator.validate(base64encoded, 'mac', {
      kid: 'Symmetric256',
      issuer: 'eyevinn',
      audience: ['one', 'three']
    });
    expect(cat).toBeDefined();
  });

  test('fail if token has an invalid audience', async () => {
    // {"aud": ["one", "two"]}
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2V6MDgmNvbmVjdHdvBhpn12R8BRpn12R8WCAdnSbUN4KbIvaHLn-q4f4YRpfq6ERYotByjbIyZ-EkfQ'
    await expect(
      validator.validate(base64encoded, 'mac', {
        kid: 'Symmetric256',
        issuer: 'eyevinn',
        audience: ['three']
      })
    ).rejects.toThrow(InvalidAudienceError);
  });
});
