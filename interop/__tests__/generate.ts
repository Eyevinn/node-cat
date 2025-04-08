import { Context } from '@osaas/client-core';
import { validateCommonAccessToken } from '@osaas/client-web';
import { CAT } from '../../src';

import { testIf } from '../util';

const runInteropTests =
  process.env.INTEROP !== undefined &&
  process.env.OSC_ACCESS_TOKEN !== undefined;

describe('CAT library', () => {
  testIf(
    runInteropTests,
    'can generate a token that someone else can validate',
    async () => {
      const ctx = new Context();
      const generator = new CAT({
        keys: {
          akamai_key_hs256: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        },
        expectCwtTag: true
      });
      const token = await generator.generateFromJson(
        {
          iss: 'eyevinn',
          sub: 'jonas',
          aud: 'coap://light.example.com',
          exp: Math.floor(Date.now() / 1000) + 3600,
          nbf: 1443944944,
          iat: 1443944944,
          cti: '0b71'
        },
        {
          type: 'mac',
          alg: 'HS256',
          kid: 'akamai_key_hs256'
        }
      );
      console.log(token);
      const result = await validateCommonAccessToken(ctx, token!, {
        signingKey:
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388'
      });
      expect(result.payload.iss).toBe('eyevinn');
    }
  );
});
