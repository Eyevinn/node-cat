import { CommonAccessToken } from '..';

/**
 * Interface for a token logger
 */
export interface ITokenLogger {
  /**
   * Log a token usage
   */
  logToken(token: CommonAccessToken): Promise<void>;
}
