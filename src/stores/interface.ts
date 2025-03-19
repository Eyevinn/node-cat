import { CommonAccessToken } from "..";

export interface CTIStore {
  storeToken(token: CommonAccessToken): Promise<void>;
  getTokenCount(token: CommonAccessToken): Promise<number>;
}
