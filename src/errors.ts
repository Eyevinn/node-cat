import { CommonAccessTokenValue } from './cat';

export class KeyNotFoundError extends Error {
  constructor() {
    super(`Failed to validate token signature with any of the available keys`);
  }
}

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

export class TokenNotActiveError extends Error {
  constructor() {
    super('Token is not yet active');
  }
}

export class InvalidCatuError extends Error {
  constructor(reason: string) {
    super(reason);
  }
}

export class UriNotAllowedError extends Error {
  constructor(reason: string) {
    super(reason);
  }
}

export class RenewalClaimError extends Error {
  constructor(reason: string) {
    super(reason);
  }
}
