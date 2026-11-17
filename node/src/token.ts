import { Sha256 } from "@aws-crypto/sha256-js";
import { HttpRequest } from "@smithy/protocol-http";
import { SignatureV4 } from "@smithy/signature-v4";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@smithy/types";

export const TOKEN_TTL_MS = 15 * 60 * 1000;

export type Credentials = AwsCredentialIdentity | AwsCredentialIdentityProvider;

export interface TokenOptions {
  host: string;
  region?: string;
  credentials: Credentials;
}

const SERVER_ID_HEADER = "X-Relay-Server-Id";
const GLOBAL_HOST = "sts.amazonaws.com";
const GLOBAL_REGION = "us-east-1";
const AWS_REGION = /^[a-z]{2}(-[a-z]+)+-[0-9]$/;
const DB_HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

export async function newToken(options: TokenOptions): Promise<string> {
  const { token } = await mint(options, new Date());
  return token;
}

export async function mint(
  { host, region, credentials }: TokenOptions,
  now: Date,
): Promise<{ token: string; credentialsExpiration?: Date }> {
  const dbHost = host.toLowerCase();
  if (!DB_HOST.test(dbHost)) {
    throw new Error(
      `dbauth: ${JSON.stringify(dbHost)} is not a database hostname; pass the host from the connection string without a port`,
    );
  }
  let stsHost = GLOBAL_HOST;
  let signingRegion = GLOBAL_REGION;
  if (region) {
    if (!AWS_REGION.test(region)) {
      throw new Error(`dbauth: invalid region ${JSON.stringify(region)}`);
    }
    stsHost = regionalHost(region);
    signingRegion = region;
  }
  const resolved = typeof credentials === "function" ? await credentials() : credentials;
  const signer = new SignatureV4({
    service: "sts",
    region: signingRegion,
    credentials: resolved,
    sha256: Sha256,
    uriEscapePath: false,
    applyChecksum: false,
  });
  const request = new HttpRequest({
    method: "GET",
    protocol: "https:",
    hostname: stsHost,
    path: "/",
    query: { Action: "GetCallerIdentity", Version: "2011-06-15" },
    headers: { host: stsHost, [SERVER_ID_HEADER.toLowerCase()]: dbHost },
  });
  const signed = await signer.presign(request, {
    signingDate: now,
    expiresIn: TOKEN_TTL_MS / 1000,
  });
  return {
    token: `${stsHost}/?${encodeQuery(signed.query as Record<string, unknown>)}&${SERVER_ID_HEADER}=${escape(dbHost)}`,
    credentialsExpiration: resolved.expiration,
  };
}

function regionalHost(region: string): string {
  return region.startsWith("cn-") ? `sts.${region}.amazonaws.com.cn` : `sts.${region}.amazonaws.com`;
}

function escape(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function encodeQuery(query: Record<string, unknown>): string {
  const keys = Object.keys(query)
    .filter((k) => k !== "X-Amz-Signature")
    .sort();
  keys.push("X-Amz-Signature");
  return keys.map((k) => `${escape(k)}=${escape(String(query[k]))}`).join("&");
}
