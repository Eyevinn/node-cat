<h1 align="center">
  Node library for Common Access Token
</h1>

<div align="center">
  Node library for Common Access Token (CTA-5007)
  <br />
</div>

<div align="center">
<br />

[![npm](https://img.shields.io/npm/v/@eyevinn/cat?style=flat-square)](https://www.npmjs.com/package/@eyevinn/cat)
[![github release](https://img.shields.io/github/v/release/Eyevinn/node-cat?style=flat-square)](https://github.com/Eyevinn/node-cat/releases)
[![license](https://img.shields.io/github/license/eyevinn/node-cat.svg?style=flat-square)](LICENSE)

[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/eyevinn/node-cat/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![made with hearth by Eyevinn](https://img.shields.io/badge/made%20with%20%E2%99%A5%20by-Eyevinn-59cbe8.svg?style=flat-square)](https://github.com/eyevinn)
[![Slack](http://slack.streamingtech.se/badge.svg)](http://slack.streamingtech.se)

</div>

This is a Node library for generating and validating Common Access Tokens (CTA-5007)

## Claims Validation Support

### Core Claims

| Claim                                                     | Validate |
| --------------------------------------------------------- | -------- |
| Issuer (`iss`)                                            | Yes      |
| Audience (`aud`)                                          | Yes      |
| Expiration (`exp`)                                        | Yes      |
| Not Before (`nbf`)                                        | Yes      |
| CWT ID (`cti`)                                            | Yes      |
| Common Access Token Replay (`catreplay`)                  | No       |
| Common Access Token Probability of Rejection (`catpor`)   | No       |
| Common Access Token Version (`catv`)                      | No       |
| Common Access Token Network IP (`catnip`)                 | No       |
| Common Access Token URI (`catu`)                          | Yes      |
| Common Access Token Methods (`catm`)                      | No       |
| Common Access Token ALPN (`catalpn`)                      | No       |
| Common Access Token Header (`cath`)                       | No       |
| Common Access Token Geographic ISO3166 (`catgeoiso3166`)  | No       |
| Common Access Token Geographic Coordinate (`catgeocoord`) | No       |
| Geohash (`geohash`)                                       | No       |
| Common Access Token Altitude (`catgeoalt`)                | No       |
| Common Access Token TLS Public Key (`cattpk`)             | No       |

## Requirements

- Node version 22+

## Installation / Usage

```bash
% npm install --save @eyevinn/cat
```

### Validate CTA Common Access Token in HTTP incoming message

```javascript
import { HttpValidator } from '@eyevinn/cat';

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
  tokenMandatory: true // Optional (default: true)
  issuer: 'eyevinn',
  audience: ['one', 'two'] // Optional
});

const server = http.createServer((req, res) => {
  const result = await httpValidator.validateHttpRequest(
    req
  );
  console.log(result.claims);
  res.writeHead(result.status, { 'Content-Type': 'text/plain' });
  res.end(result.message || 'ok');
});
server.listen(8080, '127.0.0.1', () => {
  console.log('Server listening');
});
```

```bash
% curl -v -H 'CTA-Common-Access-Token: 2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGmfXP_YGGmfXQAsFGmfXQAtYINTT_KlOyhaV6NaSxFXkqJWfBagSkPkem10dysoA-C0w' http://localhost:8080/
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.7.1
> Accept: */*
> CTA-Common-Access-Token: 2D3RhEOhAQWhBFBha2FtYWlfa2V5X2hzMjU2U6MEGmfXP_YGGmfXQAsFGmfXQAtYINTT_KlOyhaV6NaSxFXkqJWfBagSkPkem10dysoA-C0w
>
* Request completely sent off
< HTTP/1.1 401 Unauthorized
< Content-Type: text/plain
< Date: Sun, 16 Mar 2025 23:11:03 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< Transfer-Encoding: chunked
<
* Connection #0 to host localhost left intact
Token has expired
```

### Validate CTA Common Access Token in a CloudFront request

```javascript
import {
  Context,
  CloudFrontResponseEvent,
  CloudFrontResponseCallback
} from 'aws-lambda';
import { HttpValidator } from '@eyevinn/cat';

export const handler = async (
  event: CloudFrontResponseEvent,
  context: Context,
  callback: CloudFrontResponseCallback
) => {
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
  const request = event.Records[0].cf.request;
  const response = event.Records[0].cf.response;
  const result = await httpValidator.validateCloudFrontRequest(request);
  response.status = result.status;
  response.statusDescription = result.message;
  if (result.claims) {
    console.log(result.claims);
  }
  callback(null, response);
};
```

### Verify token

```javascript
import { CAT } from '@eyevinn/cat';

const validator = new CAT({
  keys: {
    Symmetric256: Buffer.from(
      '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
      'hex'
    )
  }
});
const base64encoded =
  '0YRDoQEEoQRMU3ltbWV0cmljMjU2eKZkOTAxMDNhNzAxNzU2MzZmNjE3MDNhMmYyZjYxNzMyZTY1Nzg2MTZkNzA2YzY1MmU2MzZmNmQwMjY1NmE2ZjZlNjE3MzAzNzgxODYzNmY2MTcwM2EyZjJmNmM2OTY3Njg3NDJlNjU3ODYxNmQ3MDZjNjUyZTYzNmY2ZDA0MWE1NjEyYWViMDA1MWE1NjEwZDlmMDA2MWE1NjEwZDlmMDA3NDIwYjcxSKuCk/+kFmlY';
try {
  const result = await validator.validate(base64encoded, 'mac', {
    issuer: 'coap://as.example.com'
  });
  if (result.error) {
    console.log(result.error.message);
  }
  console.log(result.cat?.claims);
} catch (err) {
  // Not valid
  console.log(err);
}
```

### Generate token

```javascript
import { CAT } from '@eyevinn/cat';

const generator = new CAT({
  keys: {
    Symmetric256: Buffer.from(
      '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
      'hex'
    )
  }
});
const base64encoded = await generator.generate(
  {
    iss: 'coap://as.example.com',
    sub: 'jonas',
    aud: 'coap://light.example.com',
    exp: 1444064944,
    nbf: 1443944944,
    iat: 1443944944
  },
  {
    type: 'mac',
    alg: 'HS256',
    kid: 'Symmetric256',
    generateCwtId: true // automatically generate a random CWT Id (cti) claim (default: false)
  }
);
```

## Development

<!--Add clear instructions on how to start development of the project here -->

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)

## License

This project is licensed under the MIT License, see [LICENSE](LICENSE).

# Support

Join our [community on Slack](http://slack.streamingtech.se) where you can post any questions regarding any of our open source projects. Eyevinn's consulting business can also offer you:

- Further development of this component
- Customization and integration of this component into your platform
- Support and maintenance agreement

Contact [sales@eyevinn.se](mailto:sales@eyevinn.se) if you are interested.

# About Eyevinn Technology

[Eyevinn Technology](https://www.eyevinntechnology.se) is an independent consultant firm specialized in video and streaming. Independent in a way that we are not commercially tied to any platform or technology vendor. As our way to innovate and push the industry forward we develop proof-of-concepts and tools. The things we learn and the code we write we share with the industry in [blogs](https://dev.to/video) and by open sourcing the code we have written.

Want to know more about Eyevinn and how it is to work here. Contact us at work@eyevinn.se!
