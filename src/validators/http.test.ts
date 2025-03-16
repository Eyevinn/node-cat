import { createRequest } from 'node-mocks-http';
import { HttpValidator } from './http';

describe('HTTP Request CAT Validator', () => {
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
    const result = await httpValidator.validateHttpRequest(
      request,
      'Symmetric256'
    );
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
    const result = await httpValidator.validateHttpRequest(
      request,
      'Symmetric256'
    );
    expect(result.status).toBe(401);
  });
});
