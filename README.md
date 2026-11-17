# dbauth

Mint IAM tokens that log in to Relay databases. Your application signs the token locally with its own AWS credentials and sends it as the database password; no call to Relay is involved. [SPEC.md](SPEC.md) describes the token.

Bind a database user to an IAM role or user in the Relay dashboard, then connect as that user with a token as the password. A token lasts at most 15 minutes and works on every hostname of the database it was minted for.

| Language | Package | Directory |
| --- | --- | --- |
| Go | `github.com/relay-sh/dbauth/go` | [go/](go) |
| Node | `@relay-sh/dbauth` | [node/](node) |

## Go

```sh
go get github.com/relay-sh/dbauth/go
```

PostgreSQL with pgx:

```go
cfg, _ := config.LoadDefaultConfig(ctx)
tokens := dbauth.NewTokenSource("orders.ab1cd.db.userelay.sh", cfg.Region, cfg.Credentials)

poolCfg, _ := pgxpool.ParseConfig("postgres://orders_app@orders.ab1cd.db.userelay.sh:5432/app?sslmode=verify-full")
poolCfg.BeforeConnect = func(ctx context.Context, c *pgx.ConnConfig) error {
	token, err := tokens.Token(ctx)
	c.Password = token
	return err
}
pool, _ := pgxpool.NewWithConfig(ctx, poolCfg)
```

Valkey with valkey-go:

```go
client, _ := valkey.NewClient(valkey.ClientOption{
	InitAddress: []string{"cache.ab1cd.db.userelay.sh:6379"},
	TLSConfig:   &tls.Config{},
	AuthCredentialsFn: func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		token, err := tokens.Token(context.Background())
		return valkey.AuthCredentials{Username: "orders_app", Password: token}, err
	},
})
```

`dbauth.NewToken` mints a single token without caching.

## Node

```sh
npm install @relay-sh/dbauth @aws-sdk/credential-providers
```

PostgreSQL with node-postgres, which accepts an async `password` function and calls it for every new connection:

```ts
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { TokenSource } from "@relay-sh/dbauth";
import pg from "pg";

const tokens = new TokenSource({
  host: "orders.ab1cd.db.userelay.sh",
  region: process.env.AWS_REGION,
  credentials: fromNodeProviderChain(),
});

const pool = new pg.Pool({
  host: "orders.ab1cd.db.userelay.sh",
  user: "orders_app",
  database: "app",
  ssl: true,
  password: () => tokens.token(),
});
```

Valkey with iovalkey (an ioredis fork). It has no per-connection password callback, so refresh the password when the client schedules a reconnect; the new token is cached, and the retry delay gives it time to resolve:

```ts
import Valkey from "iovalkey";

const client = new Valkey({
  host: "cache.ab1cd.db.userelay.sh",
  port: 6379,
  tls: {},
  username: "orders_app",
  password: await tokens.token(),
});
client.on("reconnecting", async () => {
  client.options.password = await tokens.token();
});
```

`newToken` mints a single token without caching.
