import { CommonAccessToken } from '..';
import { ITokenLogger } from './interface';

export class ConsoleLogger implements ITokenLogger {
  async logToken(token: CommonAccessToken): Promise<void> {
    const json = {
      cti: token.cti,
      timestamp: Date.now(),
      iat: token.claims.iat,
      exp: token.claims.exp,
      sub: token.claims.sub
    };
    console.log(JSON.stringify(json));
  }
}
