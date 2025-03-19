import { CommonAccessTokenValue } from './cat';

/**
 * Error thrown when a key is not found for validating a token
 */
export class KeyNotFoundError extends Error {
  constructor() {
    super(`Failed to validate token signature with any of the available keys`);
  }
}

/**
 * Error thrown when an invalid claim type is found
 */
export class InvalidClaimTypeError extends Error {
  constructor(claim: string, value: CommonAccessTokenValue) {
    super(`Invalid claim type for ${claim}: ${typeof value}`);
  }
}

/**
 * Error thrown when an invalid issuer is found
 */
export class InvalidIssuerError extends Error {
  constructor(issuer: CommonAccessTokenValue | undefined) {
    super(`Invalid issuer: ${issuer || 'undefined'}`);
  }
}

/**
 * Error thrown when token has expired
 */
export class TokenExpiredError extends Error {
  constructor() {
    super('Token has expired');
  }
}

/**
 * Error thrown when audience is not valid
 */
export class InvalidAudienceError extends Error {
  constructor(audience: string[]) {
    super(`Invalid audience: ${audience.join(', ')}`);
  }
}

/**
 * Error thrown when token is not yet active
 */
export class TokenNotActiveError extends Error {
  constructor() {
    super('Token is not yet active');
  }
}

/**
 * Error thrown when CATU claim is invalid
 */
export class InvalidCatuError extends Error {
  constructor(reason: string) {
    super(reason);
  }
}

/**
 * Error thrown when trying to access a URI that does not match the allowed URIs
 */
export class UriNotAllowedError extends Error {
  constructor(reason: string) {
    super(reason);
  }
}

/**
 * Error thrown when trying to renew a claim that is not renewable
 */
export class RenewalClaimError extends Error {
  constructor(reason: string) {
    super(reason);
  }
}

/**
 * Error thrown when trying to replay a token that is not allowed to be replayed
 */
export class ReplayNotAllowedError extends Error {
  constructor(count: number) {
    super(`Replay not allowed: ${count}`);
  }
}

/**
 * Error thrown when a token is detected for invalid reuse
 */
export class InvalidReuseDetected extends Error {
  constructor() {
    super(`Invalid reuse detected`);
  }
}
