import { createRequest } from 'node-mocks-http';
import { HttpValidator, NoTokenFoundError } from './http';
import { CAT } from '..';

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
});
