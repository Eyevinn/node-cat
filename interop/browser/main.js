import { CAT } from '@eyevinn/cat';

const output = document.getElementById('output');
const generateBtn = document.getElementById('generateToken');

const fromHexString = (hexString) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const toHexString = (bytes) =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

async function testCAT() {
  try {
    // Generate random key for testing
    const key = fromHexString(
      '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388'
    );

    const cat = new CAT({
      keys: {
        Symmetric256: key
      }
    });

    const token = await cat.generate(
      {
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        aud: 'test-audience'
      },
      {
        type: 'mac',
        alg: 'HS256',
        kid: 'Symmetric256',
        generateCwtId: true
      }
    );

    // Validate the generated token
    const result = await cat.validate(token, 'mac', {
      issuer: 'test-issuer',
      audience: ['test-audience']
    });

    output.textContent = JSON.stringify(
      {
        token,
        claims: result.cat?.claims
      },
      null,
      2
    );
  } catch (err) {
    output.textContent = `Error: ${err.message}`;
    console.error(err);
  }
}

generateBtn.addEventListener('click', testCAT);
