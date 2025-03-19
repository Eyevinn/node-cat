import { Redis } from 'ioredis';
import { ICTIStore } from './interface';
import { CommonAccessToken } from '..';

/**
 * Redis based store for tracking token usage
 */
export class RedisCTIStore implements ICTIStore {
  private client: Redis;

  constructor(redisUrl: URL) {
    this.client = new Redis(redisUrl.toString());
  }

  /**
   * Store a token in the store and return the number of times the token has been stored
   */
  async storeToken(token: CommonAccessToken): Promise<number> {
    const cti = token.cti;
    if (cti) {
      const count = await this.client.incr(cti);
      return count;
    }
    return 0;
  }

  /**
   * Get the number of times a token has been stored
   */
  async getTokenCount(token: CommonAccessToken): Promise<number> {
    const cti = token.cti;
    if (cti) {
      return parseInt((await this.client.get(cti)) || '0');
    }
    return 0;
  }
}
