import { CommonAccessToken } from '..';

export interface ITokenLogger {
  logToken(token: CommonAccessToken): Promise<void>;
}
