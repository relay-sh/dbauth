# dbauth

Mint IAM tokens that log in to Relay databases. Your application signs the token locally with its own AWS credentials and sends it as the database password; no call to Relay is involved. [SPEC.md](SPEC.md) describes the token.

Bind a database user to an IAM role or user in the Relay dashboard, then connect as that user with a token as the password. A token lasts at most 15 minutes and works on every hostname of the database it was minted for.

| Language | Package | Directory |
| --- | --- | --- |
| Go | `github.com/relay-sh/dbauth/go` | [go/](go) |
| Node | `@relay-sh/dbauth` | [node/](node) |
| Python | `relay-dbauth` | [python/](python) |
| Java | `sh.userelay:dbauth` | [java/](java) |

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

## Python

```sh
pip install relay-dbauth
```

PostgreSQL with psycopg 3:

```python
import boto3, psycopg
from relay_dbauth import TokenSource

session = boto3.Session()
tokens = TokenSource("orders.ab1cd.db.userelay.sh", session.region_name, session.get_credentials())

conn = psycopg.connect(
    "postgresql://orders_app@orders.ab1cd.db.userelay.sh:5432/app?sslmode=verify-full",
    password=tokens.token(),
)
```

Valkey with valkey-py (redis-py works the same with `redis.credentials.CredentialProvider`):

```python
import valkey
from valkey.credentials import CredentialProvider

class RelayCredentials(CredentialProvider):
    def get_credentials(self):
        return "orders_app", tokens.token()

client = valkey.Valkey(host="cache.ab1cd.db.userelay.sh", port=6379, ssl=True, credential_provider=RelayCredentials())
```

`relay_dbauth.new_token` mints a single token without caching.

## Java

Java 11 or newer, built on the AWS SDK for Java v2.

```xml
<dependency>
  <groupId>sh.userelay</groupId>
  <artifactId>dbauth</artifactId>
  <version>0.1.0</version>
</dependency>
```

PostgreSQL with JDBC:

```java
TokenSource tokens = new TokenSource("orders.ab1cd.db.userelay.sh", "us-east-1", DefaultCredentialsProvider.create());

Connection conn = DriverManager.getConnection(
    "jdbc:postgresql://orders.ab1cd.db.userelay.sh:5432/app?sslmode=verify-full", "orders_app", tokens.token());
```

HikariCP reads the password once from its config, so a pool configured with `setPassword` cannot open connections after the token expires. Give it a `DataSource` that asks the `TokenSource` for every new connection:

```java
PGSimpleDataSource source = new PGSimpleDataSource() {
    @Override
    public Connection getConnection() throws SQLException {
        return super.getConnection(getUser(), tokens.token());
    }
};
source.setURL("jdbc:postgresql://orders.ab1cd.db.userelay.sh:5432/app?sslmode=verify-full");
source.setUser("orders_app");

HikariConfig config = new HikariConfig();
config.setDataSource(source);
HikariDataSource pool = new HikariDataSource(config);
```

Valkey with Lettuce:

```java
RedisURI uri = RedisURI.builder()
    .withHost("cache.ab1cd.db.userelay.sh").withPort(6379).withSsl(true)
    .withAuthentication(RedisCredentialsProvider.from(() -> RedisCredentials.just("orders_app", tokens.token())))
    .build();
RedisClient client = RedisClient.create(uri);
```

`DbAuth.newToken` mints a single token without caching.
