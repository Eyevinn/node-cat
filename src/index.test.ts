import { CAT } from '.';

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
        iss: 'coap://as.example.com',
        sub: 'jonas',
        aud: 'coap://light.example.com',
        exp: 1444064944,
        nbf: 1443944944,
        iat: 1443944944,
        cti: '0b71'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );
    expect(base64encoded).toBeDefined();
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
    const cat = await validator.validate(base64encoded!, 'mac', {
      kid: 'Symmetric256'
    });
    expect(cat).toBeDefined();
    expect(cat!.claims).toEqual({
      iss: 'coap://as.example.com',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71'
    });
  });

  test('can validate a MAC:ed token with standard claims', async () => {
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
    const cat = await validator.validate(base64encoded, 'mac', {
      kid: 'Symmetric256'
    });
    expect(cat).toBeDefined();
    expect(cat!.claims).toEqual({
      iss: 'coap://as.example.com',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71'
    });
  });
});
