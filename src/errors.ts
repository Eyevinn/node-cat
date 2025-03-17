import { CommonAccessTokenValue } from './cat';

export class InvalidClaimTypeError extends Error {
  constructor(claim: string, value: CommonAccessTokenValue) {
    super(`Invalid claim type for ${claim}: ${typeof value}`);
  }
}

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

export class InvalidAudienceError extends Error {
  constructor(audience: string[]) {
    super(`Invalid audience: ${audience.join(', ')}`);
  }
}
