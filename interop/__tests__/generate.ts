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
          Symmetric256: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        }
      });
      const token = await generator.generate(
        {
          iss: 'eyevinn',
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
      const result = await validateCommonAccessToken(ctx, token!, {
        signingKey:
          '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388'
      });
      expect(result.payload.iss).toBe('eyevinn');
    }
  );
});
