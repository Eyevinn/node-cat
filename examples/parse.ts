import { CAT } from '../src';

async function main() {
  const parser = new CAT({
    keys: {
      Symmetric256: Buffer.from(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        'hex'
      )
    }
  });
  const result = await parser.validate(process.argv[2], 'mac', {
    issuer: 'eyevinn'
  });
  console.dir(result, { depth: null });
}

main();
