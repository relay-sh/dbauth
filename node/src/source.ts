import { mint, TOKEN_TTL_MS, type Credentials } from "./token.js";

export const REFRESH_BEFORE_MS = 2 * 60 * 1000;

export interface TokenSourceOptions {
  host: string;
  region?: string;
  credentials: Credentials;
  now?: () => Date;
}

export class TokenSource {
  private readonly options: TokenSourceOptions;
  private readonly now: () => Date;
  private cached?: { token: string; expires: number };
  private inflight?: Promise<string>;

  constructor(options: TokenSourceOptions) {
    this.options = options;
    this.now = options.now ?? (() => new Date());
  }

  token(): Promise<string> {
    const now = this.now().getTime();
    if (this.cached && now < this.cached.expires - REFRESH_BEFORE_MS) {
      return Promise.resolve(this.cached.token);
    }
    this.inflight ??= this.refresh().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }

  private async refresh(): Promise<string> {
    const now = this.now();
    const { token, credentialsExpiration } = await mint(this.options, now);
    let expires = now.getTime() + TOKEN_TTL_MS;
    if (credentialsExpiration && credentialsExpiration.getTime() < expires) {
      expires = credentialsExpiration.getTime();
    }
    this.cached = { token, expires };
    return token;
  }
}
