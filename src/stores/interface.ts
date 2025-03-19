import { CommonAccessToken } from '..';

/**
 * Interface for a CAT store
 */
export interface ICTIStore {
  /**
   * Store a token in the store and return the number of times the token has been stored
   */
  storeToken(token: CommonAccessToken): Promise<number>;
  /**
   * Get the number of times a token has been stored
   */
  getTokenCount(token: CommonAccessToken): Promise<number>;
}
