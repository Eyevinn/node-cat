import { CommonAccessToken, CommonAccessTokenFactory } from './cat';
import { CommonAccessTokenRenewal } from './catr';

describe('CAT', () => {
  test('can create a CAT object and return claims as JSON', () => {
    const claims = {
      iss: 'coap://as.example.com',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71',
      catv: 1
    };
    const cwt = new CommonAccessToken(claims);
    expect(cwt.claims).toEqual(claims);
  });

  test('can MAC a CAT object with CWT Tag', async () => {
    const claims = {
      iss: 'coap://jonas.example.com',
      nbf: 1741985961,
      iat: 1741985961,
      catv: 1
    };
    const cat = new CommonAccessToken(claims);
    const key = {
      k: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      ),
      kid: 'Symmetric256'
    };
    await cat.mac(key, 'HS256');
    expect(cat.raw).toBeDefined();
    const macHex = cat.raw?.toString('hex');
    const token = Buffer.from(macHex!, 'hex');
    const newCat = new CommonAccessToken({});
    await newCat.parse(token, key, { expectCwtTag: true });
    expect(newCat.claims).toEqual(claims);
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
    await cat.sign(signKey, 'ES256');
    const signedHex = cat.raw?.toString('hex');
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
    await cat.verify(token, verifyKey);
    const claimsWithCatv = { ...claims, catv: 1 };
    expect(cat.claims).toEqual(claimsWithCatv);
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

  test('can provide information about renewal mechanism', async () => {
    const cat = new CommonAccessToken({
      iss: 'eyevinn',
      catr: CommonAccessTokenRenewal.fromDict({
        type: 'header',
        'header-name': 'cta-common-access-token'
      }).payload
    });
    expect(cat.claims.catr).toEqual({
      type: 'header',
      'header-name': 'cta-common-access-token'
    });
  });

  test('can create a CAT object from a dict', async () => {
    const cat = CommonAccessTokenFactory.fromDict({
      iss: 'eyevinn',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71',
      catr: {
        type: 'header',
        'header-name': 'cta-common-access-token',
        'header-params': ['value1'],
        'cookie-name': 'myname',
        'cookie-params': ['cookievalue']
      }
    });
    expect(cat.claims).toEqual({
      iss: 'eyevinn',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      cti: '0b71',
      catr: {
        type: 'header',
        'header-name': 'cta-common-access-token',
        'header-params': ['value1'],
        'cookie-name': 'myname',
        'cookie-params': ['cookievalue']
      },
      catv: 1
    });
  });

  test('can create a CAT object from a dict with tags', async () => {
    const cat = new CommonAccessToken({
      1: 'eyevinn',
      2: 'jonas',
      3: 'coap://light.example.com',
      4: 1444064944,
      5: 1443944944,
      6: 1443944944,
      323: {
        0: 1,
        1: 60,
        2: 10,
        5: ['Secure', 'HttpOnly', 'Domain=.streaming.a2d.tv']
      } as any
    });
    expect(cat.claims).toEqual({
      iss: 'eyevinn',
      sub: 'jonas',
      aud: 'coap://light.example.com',
      exp: 1444064944,
      nbf: 1443944944,
      iat: 1443944944,
      catr: {
        type: 'cookie',
        expadd: 60,
        deadline: 10,
        'cookie-params': ['Secure', 'HttpOnly', 'Domain=.streaming.a2d.tv']
      },
      catv: 1
    });
  });

  test('can determine whether the token should be renewed', async () => {
    const now = Math.floor(Date.now() / 1000);
    const cat = new CommonAccessToken({
      iss: 'eyevinn',
      exp: now + 30,
      catr: CommonAccessTokenRenewal.fromDict({
        type: 'automatic',
        expadd: 60
      }).payload
    });
    expect(cat.shouldRenew).toBe(true);
    const cat2 = new CommonAccessToken({
      iss: 'eyevinn',
      exp: now + 100,
      catr: CommonAccessTokenRenewal.fromDict({
        type: 'automatic',
        expadd: 60
      }).payload
    });
    expect(cat2.shouldRenew).toBe(false);
    const cat3 = new CommonAccessToken({
      iss: 'eyevinn',
      exp: now + 100,
      catr: CommonAccessTokenRenewal.fromDict({
        type: 'automatic',
        expadd: 60,
        deadline: 105
      }).payload
    });
    expect(cat3.shouldRenew).toBe(true);
  });
});
