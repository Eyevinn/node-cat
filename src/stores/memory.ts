import { CommonAccessToken } from '..';
import { CTIStore } from './interface';

export class MemoryCTIStore implements CTIStore {
  private store: { [key: string]: number } = {};

  async storeToken(token: CommonAccessToken): Promise<void> {
    const cti = token.cti;
    if (cti) {
      if (this.store[cti]) {
        this.store[cti] += 1;
      } else {
        this.store[cti] = 1;
      }
    }
  }

  async getTokenCount(token: CommonAccessToken): Promise<number> {
    const cti = token.cti;
    if (cti) {
      return this.store[cti] || 0;
    }
    return 0;
  }
}
