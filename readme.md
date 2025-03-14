<h1 align="center">
  Node library for Common Access Token
</h1>

<div align="center">
  Node library for Common Access Token (CTA-5007)
  <br />
</div>

<div align="center">
<br />

[![npm](https://img.shields.io/npm/v/@eyevinn/node-cat?style=flat-square)](https://www.npmjs.com/package/@eyevinn/node-cat)
[![github release](https://img.shields.io/github/v/release/Eyevinn/node-cat?style=flat-square)](https://github.com/Eyevinn/node-cat/releases)
[![license](https://img.shields.io/github/license/eyevinn/node-cat.svg?style=flat-square)](LICENSE)

[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/eyevinn/node-cat/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![made with hearth by Eyevinn](https://img.shields.io/badge/made%20with%20%E2%99%A5%20by-Eyevinn-59cbe8.svg?style=flat-square)](https://github.com/eyevinn)
[![Slack](http://slack.streamingtech.se/badge.svg)](http://slack.streamingtech.se)

</div>

This is a Node library for generating and validating Common Access Tokens (CTA-5007)

## Requirements

- Node version 22+

## Installation / Usage

```bash
% npm install --save @eyevinn/cat
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
    iat: 1443944944,
    cti: '0b71'
  },
  {
    type: 'mac',
    alg: 'HS256',
    kid: 'Symmetric256'
  }
);
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
  '0YRDoQEEoQRMU3ltbWV0cmljMjU2eKZkOTAxMDNhNzAxNzU2MzZmNjE3MDNhMmYyZjYxNzMyZTY1Nzg2MTZkNzA2YzY1MmU2MzZmNmQwMjY1NmE2ZjZlNjE3MzAzNzgxODYzNmY2MTcwM2EyZjJmNmM2OTY3Njg3NDJlNjU3ODYxNmQ3MDZjNjUyZTYzNmY2ZDA0MWE1NjEyYWViMDA1MWE1NjEwZDlmMDA2MWE1NjEwZDlmMDA3NDIwYjcxSKuCk/+kFmlY'
const cat = await validator.validate(base64encoded, 'mac', {
  kid: 'Symmetric256'
});
console.log(cat.claims);
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
