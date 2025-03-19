import { CommonAccessToken } from '..';

export interface ICTIStore {
  storeToken(token: CommonAccessToken): Promise<number>;
  getTokenCount(token: CommonAccessToken): Promise<number>;
}
