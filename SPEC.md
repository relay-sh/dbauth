# Token format

A Relay IAM token is a presigned AWS STS `GetCallerIdentity` request, sent as the database password. The database's IAM gateway replays it against STS to learn the caller's identity and checks it against the user's bound principal. Every implementation in this repository must produce the tokens in `testvectors/tokens.json` byte for byte.

## Inputs

- `host`: the database hostname from the connection string, lowercased, without a port.
- `region`: the AWS region whose STS endpoint signs the request, or empty for the global endpoint.
- AWS credentials: access key ID, secret access key, and the session token when the credentials are temporary.
- `time`: the signing time, in UTC.

## Construction

1. The STS host is `sts.<region>.amazonaws.com`, `sts.<region>.amazonaws.com.cn` for regions starting with `cn-`, or `sts.amazonaws.com` (signing region `us-east-1`) when `region` is empty.
2. Build `GET https://<sts host>/` with the query `Action=GetCallerIdentity`, `Version=2011-06-15` and `X-Amz-Expires=900`, and the header `X-Relay-Server-Id: <host>`.
3. Presign it with AWS Signature Version 4 in the query string: service `sts`, the signing region from step 1, and the payload hash of an empty body. The signed headers are `host;x-relay-server-id`. Temporary credentials add `X-Amz-Security-Token`.
4. Drop the leading `https://` from the presigned URL and append `&X-Relay-Server-Id=<host>`, URL-encoded. This unsigned copy lets the gateway see which host the token was minted for; the signed header is what STS checks.

## Validity

A token is valid for 15 minutes from its signing time, or until the credentials that signed it expire, whichever comes first. A token minted for any hostname of a database is accepted on every hostname of that database (rw, ro, each node, private endpoints), so one token per database is enough. Clients should cache it and mint the next one about 2 minutes before it expires.

## Test vectors

`testvectors/tokens.json` holds fixed inputs and the expected token for each. In a test that signs with the same access key ID and two different secrets on the same date, use a different key ID per secret: SigV4 signers cache the derived signing key per key ID and date.
