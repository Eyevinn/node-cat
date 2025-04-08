import { CAT } from '../src';

async function main() {
  const generator = new CAT({
    keys: {
      Symmetric256: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      )
    },
    expectCwtTag: true
  });
  const base64encoded = await generator.generateFromJson(
    {
      iss: 'eyevinn',
      sub: 'jonas',
      aud: 'one',
      exp: Math.floor(Date.now() / 1000) + 120,
      iat: Math.floor(Date.now() / 1000),
      catr: {
        type: 'header',
        'header-name': 'cta-common-access-token',
        expadd: 120,
        deadline: 60
      },
      catif: {
        exp: [
          307,
          {
            Location: 'https://auth.example.net/?CAT='
          },
          'Symmetric256'
        ]
      }
    },
    {
      type: 'mac',
      alg: 'HS256',
      kid: 'Symmetric256',
      generateCwtId: true // automatically generate a random CWT Id (cti) claim (default: false)
    }
  );
  console.log(base64encoded);
}

main();
