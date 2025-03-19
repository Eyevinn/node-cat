import { CommonAccessToken } from '..';

export interface CTIStore {
  storeToken(token: CommonAccessToken): Promise<number>;
  getTokenCount(token: CommonAccessToken): Promise<number>;
}
