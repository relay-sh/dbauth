import { describe, expect, it } from "vitest";
import { REFRESH_BEFORE_MS, TOKEN_TTL_MS, TokenSource } from "../src/index.js";

const base = new Date("2026-01-02T03:04:05Z").getTime();

function setup(expiration?: () => Date | undefined) {
  let clock = base;
  let calls = 0;
  const source = new TokenSource({
    host: "orders.ab1cd.db.userelay.sh",
    region: "us-east-1",
    now: () => new Date(clock),
    credentials: async () => {
      calls++;
      await Promise.resolve();
      return { accessKeyId: `AKIDNODE${calls}`, secretAccessKey: "secret", expiration: expiration?.() };
    },
  });
  return { source, advance: (ms: number) => (clock += ms), calls: () => calls };
}

describe("TokenSource", () => {
  it("caches until two minutes before expiry", async () => {
    const { source, advance, calls } = setup();
    const first = await source.token();
    advance(TOKEN_TTL_MS - REFRESH_BEFORE_MS - 1);
    expect(await source.token()).toBe(first);
    expect(calls()).toBe(1);
    advance(1);
    const second = await source.token();
    expect(second).not.toBe(first);
    expect(calls()).toBe(2);
  });

  it("refreshes earlier when the credentials expire first", async () => {
    const { source, advance, calls } = setup(() => new Date(base + 5 * 60 * 1000));
    await source.token();
    advance(3 * 60 * 1000);
    await source.token();
    expect(calls()).toBe(2);
  });

  it("ignores a credentials expiration later than the token ttl", async () => {
    const { source, advance, calls } = setup(() => new Date(base + 60 * 60 * 1000));
    await source.token();
    advance(TOKEN_TTL_MS - REFRESH_BEFORE_MS - 1);
    await source.token();
    expect(calls()).toBe(1);
  });

  it("shares one in-flight mint between concurrent callers", async () => {
    const { source, calls } = setup();
    const [a, b, c] = await Promise.all([source.token(), source.token(), source.token()]);
    expect(a).toBe(b);
    expect(b).toBe(c);
    expect(calls()).toBe(1);
  });

  it("retries after a failed mint", async () => {
    let fail = true;
    const source = new TokenSource({
      host: "orders.ab1cd.db.userelay.sh",
      credentials: async () => {
        if (fail) throw new Error("boom");
        return { accessKeyId: "AKIDNODERETRY", secretAccessKey: "s" };
      },
    });
    await expect(source.token()).rejects.toThrow("boom");
    fail = false;
    expect(await source.token()).toContain("sts.amazonaws.com/");
  });

  it("uses the system clock by default", async () => {
    const source = new TokenSource({
      host: "orders.ab1cd.db.userelay.sh",
      credentials: { accessKeyId: "AKIDNODECLOCK", secretAccessKey: "s" },
    });
    expect(await source.token()).toBe(await source.token());
  });
});
