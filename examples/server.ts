import http from 'node:http';

import { HttpValidator, RedisCTIStore } from '../src';

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
  store: new RedisCTIStore(
    new URL(process.env.REDIS_URL || 'redis://localhost:6379')
  )
});

const server = http.createServer(async (req, res) => {
  const result = await httpValidator.validateHttpRequest(req, res);
  console.log(result);
  res.writeHead(result.status, { 'Content-Type': 'text/plain' });
  res.end(result.message || 'ok');
});
server.listen(8080, '127.0.0.1', () => {
  console.log('Server listening');
});
