import { Context } from '@osaas/client-core';
import { generateCommonAccessToken } from '@osaas/client-web';
import { CAT } from '../../src';
import { testIf } from '../util';

const runInteropTests =
  process.env.INTEROP !== undefined &&
  process.env.OSC_ACCESS_TOKEN !== undefined;

describe('CAT library can validate a token that someone else has generated', () => {
  testIf(
    runInteropTests,
    'issuer',
    async () => {
      const ctx = new Context();
      const validator = new CAT({
        keys: {
          Symmetric256: Buffer.from(
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
            'hex'
          )
        },
        expectCwtTag: true
      });
      const token = await generateCommonAccessToken(
        ctx,
        {
          iss: 'eyevinn',
          sub: 'jonas'
        },
        {
          signingKey:
            '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388'
        }
      );
      const result = await validator.validate(token, 'mac', {
        issuer: 'eyevinn'
      });
      expect(result.error).not.toBeDefined();
      expect(result.cat).toBeDefined();
      expect(result.cat!.claims.iss).toBe('eyevinn');
    },
    10000
  );
});
