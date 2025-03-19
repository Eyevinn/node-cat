import { CommonAccessToken } from '..';
import { ITokenLogger } from './interface';

/**
 * Console based logger for token usage
 */
export class ConsoleLogger implements ITokenLogger {
  /**
   * Log when a token is used on stdout
   */
  async logToken(token: CommonAccessToken): Promise<void> {
    const json = {
      cti: token.cti,
      timestamp: Date.now(),
      iat: token.claims.iat,
      exp: token.claims.exp,
      sub: token.claims.sub
    };
    console.log(JSON.stringify(json));
  }
}
