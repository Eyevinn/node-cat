import { createRequest, createResponse } from 'node-mocks-http';
import { HttpValidator, NoTokenFoundError } from './http';
import { CAT } from '..';
import { CommonAccessTokenRenewal } from '../catr';

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
    const request = createRequest({
      method: 'GET',
      headers: {
        'CTA-Common-Access-Token': base64encoded
      }
    });
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(result.status).toBe(200);
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

  test('can autorenew when autorenew is enabled and only when token is about to expire', async () => {
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
    console.log(request.url);
    const response = createResponse();
    const result = await httpValidator.validateHttpRequest(request, response);
    expect(response.getHeader('Location')).toBeDefined();
  });
});
