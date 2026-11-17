import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { mint, newToken } from "../src/token.js";

interface Vector {
  name: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  host: string;
  region?: string;
  time: string;
  token: string;
}

const vectors: Vector[] = JSON.parse(readFileSync(new URL("../../testvectors/tokens.json", import.meta.url), "utf8"));

describe("shared vectors", () => {
  for (const v of vectors) {
    it(v.name, async () => {
      const { token } = await mint(
        {
          host: v.host,
          region: v.region,
          credentials: {
            accessKeyId: v.accessKeyId,
            secretAccessKey: v.secretAccessKey,
            sessionToken: v.sessionToken,
          },
        },
        new Date(v.time),
      );
      expect(token).toBe(v.token);
    });
  }
});

describe("newToken", () => {
  it("lowercases the host and accepts a credentials provider", async () => {
    const token = await newToken({
      host: "Orders.AB1CD.db.userelay.sh",
      region: "us-east-1",
      credentials: async () => ({ accessKeyId: "AKIDNODE", secretAccessKey: "secret" }),
    });
    expect(token.startsWith("sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&")).toBe(true);
    expect(token.endsWith("&X-Relay-Server-Id=orders.ab1cd.db.userelay.sh")).toBe(true);
    expect(token).toContain("X-Amz-SignedHeaders=host%3Bx-relay-server-id");
    expect(token).toContain("X-Amz-Expires=900");
  });

  it.each(["orders.ab1cd.db.userelay.sh:5432", "localhost", "", "bad_host.example.com", "a..b"])(
    "rejects host %j",
    async (host) => {
      await expect(
        newToken({ host, credentials: { accessKeyId: "AKIDNODE", secretAccessKey: "s" } }),
      ).rejects.toThrow(/not a database hostname/);
    },
  );

  it.each(["US-EAST-1", "us-east", "mars", "us-east-1.evil.com/"])("rejects region %j", async (region) => {
    await expect(
      newToken({
        host: "a.b.example.com",
        region,
        credentials: { accessKeyId: "AKIDNODE", secretAccessKey: "s" },
      }),
    ).rejects.toThrow(/invalid region/);
  });

  it("propagates credential provider errors", async () => {
    await expect(
      newToken({
        host: "a.b.example.com",
        credentials: async () => {
          throw new Error("no creds");
        },
      }),
    ).rejects.toThrow("no creds");
  });

  it("escapes characters encodeURIComponent leaves alone", async () => {
    const { token } = await mint(
      {
        host: "a.b.example.com",
        credentials: { accessKeyId: "AKIDNODE2", secretAccessKey: "s", sessionToken: "t!'()*" },
      },
      new Date("2026-01-02T03:04:05Z"),
    );
    expect(token).toContain("X-Amz-Security-Token=t%21%27%28%29%2A");
  });

  it("reports the credentials expiration", async () => {
    const expiration = new Date("2026-01-02T03:10:00Z");
    const out = await mint(
      {
        host: "a.b.example.com",
        credentials: { accessKeyId: "AKIDNODE3", secretAccessKey: "s", expiration },
      },
      new Date("2026-01-02T03:04:05Z"),
    );
    expect(out.credentialsExpiration).toEqual(expiration);
  });
});
