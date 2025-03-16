import { CommonAccessToken, CommonAccessTokenFactory } from './cat';

describe('CAT', () => {
  test('can create a CAT object and return claims as JSON', () => {
    const claims = {
      iss: 'coap://as.example.com',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71'
    };
    const cwt = new CommonAccessToken(claims);
    expect(cwt.claims).toEqual(claims);
  });

  test('can MAC a CAT object with CWT Tag', async () => {
    const claims = {
      iss: 'coap://jonas.example.com',
      nbf: 1741985961,
      iat: 1741985961
    };
    const cat = new CommonAccessToken(claims);
    const key = {
      k: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      ),
      kid: 'Symmetric256'
    };
    const mac = await cat.mac(key, 'HS256', { addCwtTag: true });
    expect(mac.raw).toBeDefined();
    const macHex = mac.raw?.toString('hex');
    //expect(macHex).toEqual(
    //  'b9000263746167183d6576616c756558c6d18443a10104a1044c53796d6d657472696332353678a66439303130336137303137353633366636313730336132663266363137333265363537383631366437303663363532653633366636643032363536613666366536313733303337383138363336663631373033613266326636633639363736383734326536353738363136643730366336353265363336663664303431613536313261656230303531613536313064396630303631613536313064396630303734323062373148ab8293ffa4166958'
    //);
    const token = Buffer.from(macHex!, 'hex');
    const parsed = await cat.parse(token, key, { expectCwtTag: true });
    expect(parsed.claims).toEqual(claims);
  });

  test('can sign a CAT object', async () => {
    const claims = {
      iss: 'coap://as.example.com',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71'
    };
    const cat = new CommonAccessToken(claims);
    const signKey = {
      d: Buffer.from(
        '6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19',
        'hex'
      ),
      kid: 'AsymmetricECDSA256'
    };
    const signed = await cat.sign(signKey, 'ES256');
    const signedHex = signed.raw?.toString('hex');
    const token = Buffer.from(signedHex!, 'hex');
    const verifyKey = {
      x: Buffer.from(
        '143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f',
        'hex'
      ),
      y: Buffer.from(
        '60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9',
        'hex'
      ),
      kid: 'AsymmetricECDSA256'
    };
    const verified = await cat.verify(token, verifyKey);
    expect(verified.claims).toEqual(claims);
  });

  test('can create a CAT object from a signed base64 encoded token', async () => {
    const base64encoded =
      '0oRDoQEmoQRSQXN5bW1ldHJpY0VDRFNBMjU2eKZkOTAxMDNhNzAxNzU2MzZmNjE3MDNhMmYyZjYxNzMyZTY1Nzg2MTZkNzA2YzY1MmU2MzZmNmQwMjY1NmE2ZjZlNjE3MzAzNzgxODYzNmY2MTcwM2EyZjJmNmM2OTY3Njg3NDJlNjU3ODYxNmQ3MDZjNjUyZTYzNmY2ZDA0MWE1NjEyYWViMDA1MWE1NjEwZDlmMDA2MWE1NjEwZDlmMDA3NDIwYjcxWEDctMzQNy7mvRZNvwmyJ2b5WG+Q1erTbN4SCFyM05lnBH/fBFJJ2QR20OypFvHd2veW3fzGsRY/ZRM1dxUE1Mfb';
    const verifyKey = {
      x: Buffer.from(
        '143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f',
        'hex'
      ),
      y: Buffer.from(
        '60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9',
        'hex'
      ),
      kid: 'AsymmetricECDSA256'
    };
    const cat = await CommonAccessTokenFactory.fromSignedToken(
      base64encoded,
      verifyKey
    );
    expect(cat.claims).toEqual({
      iss: 'coap://as.example.com',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71'
    });
  });

  test('can create a CAT object from a mac:ed base64 encoded token', async () => {
    const base64encoded =
      '0YRDoQEEoQRMU3ltbWV0cmljMjU2eKZkOTAxMDNhNzAxNzU2MzZmNjE3MDNhMmYyZjYxNzMyZTY1Nzg2MTZkNzA2YzY1MmU2MzZmNmQwMjY1NmE2ZjZlNjE3MzAzNzgxODYzNmY2MTcwM2EyZjJmNmM2OTY3Njg3NDJlNjU3ODYxNmQ3MDZjNjUyZTYzNmY2ZDA0MWE1NjEyYWViMDA1MWE1NjEwZDlmMDA2MWE1NjEwZDlmMDA3NDIwYjcxSKuCk/+kFmlY';
    const key = {
      k: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      ),
      kid: 'Symmetric256'
    };
    const cat = await CommonAccessTokenFactory.fromMacedToken(
      base64encoded,
      key,
      false
    );
    expect(cat.claims).toEqual({
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
