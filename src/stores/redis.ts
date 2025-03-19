import { Redis } from 'ioredis';
import { ICTIStore } from './interface';
import { CommonAccessToken } from '..';

export class RedisCTIStore implements ICTIStore {
  private client: Redis;

  constructor(redisUrl: URL) {
    this.client = new Redis(redisUrl.toString());
  }

  async storeToken(token: CommonAccessToken): Promise<number> {
    const cti = token.cti;
    if (cti) {
      const count = await this.client.incr(cti);
      return count;
    }
    return 0;
  }

  async getTokenCount(token: CommonAccessToken): Promise<number> {
    const cti = token.cti;
    if (cti) {
      return parseInt((await this.client.get(cti)) || '0');
    }
    return 0;
  }
}
