import { createRequest, createResponse } from 'node-mocks-http';
import { HttpValidator, NoTokenFoundError } from './http';
import {
  CAT,
  CommonAccessToken,
  ICTIStore,
  ITokenLogger,
  MemoryCTIStore
} from '..';
import { CommonAccessTokenRenewal } from '../catr';
import { generateRandomHex } from '../util';

describe('HTTP Request CAT Validator', () => {
  test('fail to validate token in CTA-Common-Access-Token header with wrong signature', async () => {
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token':
          '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGnUCOrsGGmfXRKwFGmfXRKxYIOM6yRx830uqAamWFv1amFYRa5vaV2z5lIQTqFEvFh8z'
      }
    });
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32b05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).not.toBe(200);
    expect(result.status).toBe(401);
    expect(result.message).toBe(
      'Failed to validate token signature with any of the available keys'
    );
  });

  test('can validate token in CTA-Common-Access-Token header', async () => {
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token':
          '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGnUCOrsGGmfXRKwFGmfXRKxYIOM6yRx830uqAamWFv1amFYRa5vaV2z5lIQTqFEvFh8z'
      }
    });
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(200);
  });

  test('can validate expired token in CTA-Common-Access-Token header', async () => {
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token':
          '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGmfXP_YGGmfXQAsFGmfXQAtYINTT_KlOyhaV6NaSxFXkqJWfBagSkPkem10dysoA-C0w'
      }
    });
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(401);
  });

  test('can handle multiple keys (under rotation)', async () => {
    const generator = new CAT({
      keys: {
        keyone: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });
    const token = await generator.generate(
      {
        iss: 'eyevinn'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'keyone'
      }
    );
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': token
      }
    });
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'keyon',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        },
        {
          kid: 'keytwo',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569389',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(200);
  });

  test('can handle when CTA access token header is an array', async () => {
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': [
          '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGnUCOrsGGmfXRKwFGmfXRKxYIOM6yRx830uqAamWFv1amFYRa5vaV2z5lIQTqFEvFh8z'
        ]
      }
    });
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(200);
  });

  test('returns ok when CTA common access token is optional', async () => {
    const request = createRequest({
      method: 'GET'
    });
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    await expect(httpValidator.validateHttpRequest(request)).rejects.toThrow(
      NoTokenFoundError
    );
    const httpValidatorOptional = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn',
      tokenMandatory: false
    });
    const result = await httpValidatorOptional.validateHttpRequest(request);
    expect(result.status).toBe(200);
  });

  test('can handle request of CloudFront request type', async () => {
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'GET',
      uri: '/index.html',
      querystring: '',
      headers: {
        'cta-common-access-token': [
          {
            value:
              '2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGnUCOrsGGmfXRKwFGmfXRKxYIOM6yRx830uqAamWFv1amFYRa5vaV2z5lIQTqFEvFh8z'
          }
        ]
      }
    });
    expect(result.status).toBe(200);
  });

  test('can handle catu claims', async () => {
    /**
     * This token was generated with the following catu claims:
     *  scheme: {
     *    'exact-match': 'https'
     *  },
     *  path: {
     *    'prefix-match': '/content'
     *  },
     *  extension: {
     *    'exact-match': '.m3u8'
     *  }
     */
    const token =
      '2D3RhEOhAQW5AAFhNExTeW1tZXRyaWMyNTZYO9kBA6IBZ2V5ZXZpbm4ZATjZAQOjANkBA6EAZWh0dHBzA9kBA6EBaC9jb250ZW50CNkBA6EAZS5tM3U4WCCD42NQN46M44nvyg4eD4tKUo2+spMlXhtOHW3IiUFiXg==';
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'GET',
      uri: '/content/path/file.m3u8',
      querystring: '',
      headers: {
        'cta-common-access-token': [
          {
            value: token
          }
        ],
        host: [
          {
            key: 'Host',
            value: 'example.com'
          }
        ]
      }
    });
    expect(result.status).toBe(200);
  });

  test('can get parsed claims from token', async () => {
    const token =
      '2D3RhEOhAQW5AAFhNExTeW1tZXRyaWMyNTZYO9kBA6IBZ2V5ZXZpbm4ZATjZAQOjANkBA6EAZWh0dHBzA9kBA6EBaC9jb250ZW50CNkBA6EAZS5tM3U4WCCD42NQN46M44nvyg4eD4tKUo2+spMlXhtOHW3IiUFiXg==';
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'GET',
      uri: '/content/path/file.m3u8',
      querystring: '',
      headers: {
        'cta-common-access-token': [
          {
            value: token
          }
        ],
        host: [
          {
            key: 'Host',
            value: 'example.com'
          }
        ]
      }
    });
    expect(result.status).toBe(200);
    expect(result.claims).toEqual({
      iss: 'eyevinn',
      catu: {
        scheme: { 'exact-match': 'https' },
        path: { 'prefix-match': '/content' },
        extension: { 'exact-match': '.m3u8' }
      }
    });
  });
});

describe('HTTP Request CAT Validator with auto renew', () => {
  let generator: CAT;
  let base64encoded: string | undefined;
  beforeEach(async () => {
    // Prepare a token that is about to expire
    generator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      },
      expectCwtTag: true
    });

    const now = Math.floor(Date.now() / 1000);
    base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        exp: now + 60,
        catr: CommonAccessTokenRenewal.fromDict({
          type: 'automatic',
          'header-name': 'cta-common-access-token',
          'cookie-name': 'cta-common-access-token',
          'cookie-params': ['Secure', 'HttpOnly', 'Domain=.eyevinn.technology'],
          code: 301,
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
  });

  test('can autorenew when autorenew is enabled', async () => {
    // Validate and auto renew
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const now = Math.floor(Date.now() / 1000);
    base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        exp: now + 60,
        catr: CommonAccessTokenRenewal.fromDict({
          type: 'header',
          'header-name': 'cta-common-access-token',
          'cookie-name': 'cta-common-access-token',
          'header-params': ['Secure', 'HttpOnly', 'Domain=.eyevinn.technology'],
          code: 301,
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
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(result.status).toBe(200);
    expect(response.getHeader('cta-common-access-token')).toMatch(
      /^(\S+); Secure; HttpOnly; Domain=.eyevinn.technology/
    );
    expect(response.getHeader('cta-common-access-token')).toBeDefined();

    const renewDisabled = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn',
      autoRenewEnabled: false
    });
    const response2 = createResponse();
    const result2 = await renewDisabled.validateHttpRequest(request, response2);
    expect(result2.status).toBe(200);
    expect(response2.getHeader('cta-common-access-token')).toBeUndefined();
  });

  test('can autorenew and set cookie when autorenew is enabled', async () => {
    // Validate and auto renew
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const now = Math.floor(Date.now() / 1000);
    base64encoded = await generator.generateFromJson(
      {
        iss: 'eyevinn',
        exp: now + 60,
        catr: {
          type: 'cookie',
          'header-name': 'cta-common-access-token',
          'cookie-name': 'cta-common-access-token',
          'cookie-params': ['Secure', 'HttpOnly', 'Domain=.eyevinn.technology'],
          code: 301,
          expadd: 120,
          deadline: 60
        }
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(result.status).toBe(200);
    expect(response.getHeader('set-cookie')).toBeDefined();
    expect(response.getHeader('set-cookie')).toMatch(
      /^cta-common-access-token=(\S+); Secure; HttpOnly; Domain=.eyevinn.technology/
    );

    const renewDisabled = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn',
      autoRenewEnabled: false
    });
    const response2 = createResponse();
    const result2 = await renewDisabled.validateHttpRequest(request, response2);
    expect(result2.status).toBe(200);
    expect(response2.getHeader('cta-common-access-token')).toBeUndefined();
  });

  test('can autorenew when autorenew is enabled and only when token is about to expire', async () => {
    base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        exp: Math.floor(Date.now() / 1000) + 120,
        catr: CommonAccessTokenRenewal.fromDict({
          type: 'automatic',
          'header-name': 'cta-common-access-token',
          'cookie-name': 'cta-common-access-token',
          'cookie-params': ['Secure', 'HttpOnly', 'Domain=.a2d.tv'],
          code: 302,
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
    // Validate auto renew
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(result.status).toBe(200);
    expect(response.getHeader('cta-common-access-token')).not.toBeDefined();
  });

  test('can follow the directives in catif claim when no acceptable token is provided', async () => {
    const json = {
      iss: 'eyevinn',
      exp: Math.floor(Date.now() / 1000) - 60,
      cti: generateRandomHex(16),
      catif: {
        exp: [
          307,
          {
            Location: 'https://auth.example.net/'
          }
        ]
      }
    };
    base64encoded = await generator.generateFromJson(json, {
      type: 'mac',
      alg: 'HS256',
      kid: 'Symmetric256',
      generateCwtId: true
    });
    // Validate auto renew
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(response.getHeader('Location')).toBe('https://auth.example.net/');
    expect(result.status).toBe(307);
  });

  test('can generate new cat claims based on catif directives', async () => {
    const cti = generateRandomHex(16);
    const json = {
      iss: 'eyevinn',
      exp: Math.floor(Date.now() / 1000) - 60,
      cti,
      catif: {
        exp: [
          307,
          {
            Location: [
              'https://auth.example.net/?CAT=',
              {
                iss: null,
                iat: null,
                catu: {
                  host: { 'exact-match': 'auth.example.net' }
                }
              }
            ]
          },
          'Symmetric256'
        ]
      }
    };
    base64encoded = await generator.generateFromJson(json, {
      type: 'mac',
      alg: 'HS256',
      kid: 'Symmetric256',
      generateCwtId: true
    });
    // Validate auto renew
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(response.getHeader('Location')).toBeDefined();
    const location = new URL(response.getHeader('Location') as string);
    const newToken = location.searchParams.get('CAT');
    expect(newToken).toBeDefined();
    expect(result.status).toBe(307);
    const validator = new CAT({
      keys: {
        Symmetric256: Buffer.from(
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
          'hex'
        )
      }
    });
    const result2 = await validator.validate(newToken!, 'mac', {
      issuer: 'eyevinn'
    });
    expect(result2.cat?.claims.iat).toBeDefined();
    expect(result2.cat?.claims.cti).not.toEqual(cti);
  });

  test.skip('can handle autorenew of type redirect', async () => {
    // Validate auto renew
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        host: 'example.com'
      },
      url: '/index.html?cat=' + base64encoded
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(response.getHeader('Location')).toBeDefined();
  });

  test('cloudfront request with autorenew', async () => {
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'GET',
      uri: '/content/path/file.m3u8',
      querystring: '',
      headers: {
        'cta-common-access-token': [
          {
            value: base64encoded!
          }
        ],
        host: [
          {
            key: 'Host',
            value: 'example.com'
          }
        ]
      }
    });
    expect(result.status).toBe(200);
    expect(result.cfResponse.headers['cta-common-access-token']).toBeDefined();
  });

  test('cloudfront request with token as cookie', async () => {
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'GET',
      uri: '/content/path/file.m3u8',
      querystring: '',
      headers: {
        cookie: [
          {
            value: `CTA-Common-Access-Token=${base64encoded!}; Path=/; Secure; HttpOnly`
          }
        ],
        host: [
          {
            key: 'Host',
            value: 'example.com'
          }
        ]
      }
    });
    expect(result.status).toBe(200);
    expect(
      result.cfResponse.headers['cta-common-access-token']
    ).not.toBeDefined();
    expect(
      result.cfResponse.headers['set-cookie'][0].value.includes(
        'cta-common-access-token'
      )
    ).toBeTruthy();
  });

  test('cloudfront request with autorenew where token has not expired', async () => {
    base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        exp: Math.floor(Date.now() / 1000) + 120,
        catr: CommonAccessTokenRenewal.fromDict({
          type: 'automatic',
          'header-name': 'cta-common-access-token',
          'cookie-name': 'cta-common-access-token',
          code: 302,
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
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const result = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'GET',
      uri: '/content/path/file.m3u8',
      querystring: '',
      headers: {
        'cta-common-access-token': [
          {
            value: base64encoded!
          }
        ],
        host: [
          {
            key: 'Host',
            value: 'example.com'
          }
        ]
      }
    });
    expect(result.status).toBe(200);
    expect(
      result.cfResponse.headers['cta-common-access-token']
    ).not.toBeDefined();
  });
});

describe('HTTP Request CAT Validator with store', () => {
  let generator: CAT;
  beforeEach(() => {
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

  test('can validate token and store used token and increase count', async () => {
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        exp: Math.floor(Date.now() / 1000) + 120,
        cti: '0b71',
        catr: CommonAccessTokenRenewal.fromDict({
          type: 'automatic',
          'header-name': 'cta-common-access-token',
          'cookie-name': 'cta-common-access-token',
          code: 302,
          expadd: 120,
          deadline: 60
        }).payload
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );

    const store = new MemoryCTIStore();
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn',
      store
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(result.claims!.cti).toBe('0b71');
    expect(result.count).toBe(1);
    const result2 = await httpValidator.validateHttpRequest(request, response);
    expect(result2.status).toBe(200);
    expect(result2.count).toBe(2);

    const cfResult = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'GET',
      uri: '/content/path/file.m3u8',
      querystring: '',
      headers: {
        'cta-common-access-token': [
          {
            value: base64encoded!
          }
        ],
        host: [
          {
            key: 'Host',
            value: 'example.com'
          }
        ]
      }
    });
    expect(cfResult.count).toBe(3);
  });

  test('can validate token without a store', async () => {
    const base64encoded = await generator.generate(
      {
        iss: 'eyevinn',
        exp: Math.floor(Date.now() / 1000) + 120,
        cti: '0b71',
        catr: CommonAccessTokenRenewal.fromDict({
          type: 'automatic',
          'header-name': 'cta-common-access-token',
          'cookie-name': 'cta-common-access-token',
          code: 302,
          expadd: 120,
          deadline: 60
        }).payload
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256'
      }
    );

    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(result.claims!.cti).toBe('0b71');
    expect(result.count).toBeUndefined();
  });

  test('pass if a token has a claim that allows replay and it has been used multiple times', async () => {
    const base64encoded = await generator.generateFromJson(
      {
        iss: 'eyevinn',
        catreplay: 0
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn',
      store: new MemoryCTIStore()
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(200);
    const result2 = await httpValidator.validateHttpRequest(request);
    expect(result2.status).toBe(200);
  });

  test('fail if a token has a claim that does not allow replay and it has been used multiple times', async () => {
    const base64encoded = await generator.generateFromJson(
      {
        iss: 'eyevinn',
        catreplay: 1
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn',
      store: new MemoryCTIStore()
    });
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(200);
    const result2 = await httpValidator.validateHttpRequest(request);
    expect(result2.status).toBe(401);
  });

  test('can provide a simple reuse detection algorithm', async () => {
    const base64encoded = await generator.generateFromJson(
      {
        iss: 'eyevinn',
        catreplay: 2
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );

    const simpleReuseDetection = async (
      cat: CommonAccessToken,
      store?: ICTIStore,
      logger?: ITokenLogger
    ) => {
      if (store) {
        const count = await store.getTokenCount(cat);
        // Consider reuse if same token has been used more than 2 times
        // (this is a very naive example)
        return count > 2;
      }
      return true;
    };
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn',
      store: new MemoryCTIStore(),
      reuseDetection: simpleReuseDetection
    });

    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(200);
    const result2 = await httpValidator.validateHttpRequest(request);
    expect(result2.status).toBe(200);
    const result3 = await httpValidator.validateHttpRequest(request);
    expect(result3.status).toBe(401);
  });

  test('fails if an HTTP method is used that is not allowed by the claim', async () => {
    const base64encoded = await generator.generateFromJson(
      {
        iss: 'eyevinn',
        catm: ['GET', 'DELETE']
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );
    const httpValidator = new HttpValidator({
      keys: [
        {
          kid: 'Symmetric256',
          key: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      ],
      issuer: 'eyevinn'
    });

    const request = createRequest({
      method: 'POST',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const result = await httpValidator.validateHttpRequest(request);
    expect(result.status).toBe(401);
    const cfResult = await httpValidator.validateCloudFrontRequest({
      clientIp: 'dummy',
      method: 'POST',
      uri: '/content/',
      querystring: '',
      headers: {
        'cta-common-access-token': [
          {
            value: base64encoded!
          }
        ],
        host: [
          {
            key: 'Host',
            value: 'example.com'
          }
        ]
      }
    });
    expect(cfResult.status).toBe(401);
  });
});
