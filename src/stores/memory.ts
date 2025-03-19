import { CommonAccessToken } from '..';
import { ICTIStore } from './interface';

/**
 * Memory based store for tracking token usage
 */
export class MemoryCTIStore implements ICTIStore {
  private store: { [key: string]: number } = {};

  async storeToken(token: CommonAccessToken): Promise<number> {
    const cti = token.cti;
    if (cti) {
      if (this.store[cti]) {
        this.store[cti] += 1;
      } else {
        this.store[cti] = 1;
      }
      return this.store[cti];
    }
    return 0;
  }

  async getTokenCount(token: CommonAccessToken): Promise<number> {
    const cti = token.cti;
    if (cti) {
      return this.store[cti] || 0;
    }
    return 0;
  }
}
