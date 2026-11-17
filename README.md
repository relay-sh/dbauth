# dbauth

Mint IAM tokens that log in to Relay databases. Your application signs the token locally with its own AWS credentials and sends it as the database password; no call to Relay is involved. [SPEC.md](SPEC.md) describes the token.

Bind a database user to an IAM role or user in the Relay dashboard, then connect as that user with a token as the password. A token lasts at most 15 minutes and works on every hostname of the database it was minted for.

| Language | Package | Directory |
| --- | --- | --- |
| Go | `github.com/relay-sh/dbauth/go` | [go/](go) |

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
