import { CommonAccessTokenValue } from './cat';

export class InvalidIssuerError extends Error {
  constructor(issuer: CommonAccessTokenValue | undefined) {
    super(`Invalid issuer: ${issuer || 'undefined'}`);
  }
}

export class TokenExpiredError extends Error {
  constructor() {
    super('Token has expired');
  }
}
