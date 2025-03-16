import { CAT } from '.';
import { InvalidIssuerError, TokenExpiredError } from './errors';

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
    const cat = await validator.validate(
      base64encoded!,
      'mac',
      'coap://as.example.com',
      {
        kid: 'Symmetric256'
      }
    );
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
    const cat = await validator.validate(
      base64encoded,
      'mac',
      'coap://as.example.com',
      {
        kid: 'Symmetric256'
      }
    );
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
    const cat = await validator.validate(
      base64encoded,
      'mac',
      'coap://jonas.example.com',
      {
        kid: 'Symmetric256'
      }
    );
    expect(cat).toBeDefined();
    expect(cat!.claims).toEqual({
      iss: 'coap://jonas.example.com',
      iat: 1741985961,
      nbf: 1741985961
    });
  });

  test('fail if wrong issuer', async () => {
    const base64encoded =
      '0YRDoQEEoQRMU3ltbWV0cmljMjU2eKZkOTAxMDNhNzAxNzU2MzZmNjE3MDNhMmYyZjYxNzMyZTY1Nzg2MTZkNzA2YzY1MmU2MzZmNmQwMjY1NmE2ZjZlNjE3MzAzNzgxODYzNmY2MTcwM2EyZjJmNmM2OTY3Njg3NDJlNjU3ODYxNmQ3MDZjNjUyZTYzNmY2ZDA0MWE1NjEyYWViMDA1MWE1NjEwZDlmMDA2MWE1NjEwZDlmMDA3NDIwYjcxSKuCk/+kFmlY';
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
    await expect(
      validator.validate(base64encoded, 'mac', 'coap://jonas.example.com', {
        kid: 'Symmetric256'
      })
    ).rejects.toThrow(InvalidIssuerError);
  });

  test('pass if token has not expired', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGnUCOrsGGmfXRKwFGmfXRKxYIOM6yRx830uqAamWFv1amFYRa5vaV2z5lIQTqFEvFh8z';
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });
    const cat = validator.validate(base64encoded, 'mac', 'eyevinn', {
      kid: 'Symmetric256'
    });
    expect(cat).toBeDefined();
  });

  test('fail if token expired', async () => {
    const base64encoded =
      '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGmfXP_YGGmfXQAsFGmfXQAtYINTT_KlOyhaV6NaSxFXkqJWfBagSkPkem10dysoA-C0w';
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });
    await expect(
      validator.validate(base64encoded, 'mac', 'eyevinn', {
        kid: 'Symmetric256'
      })
    ).rejects.toThrow(TokenExpiredError);
  });
});
