package sh.userelay.dbauth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

/** Caches a token for one database and mints a new one shortly before it expires; safe for concurrent use. */
public final class TokenSource {
    /** How long a token stays valid, unless the credentials that signed it expire first. */
    public static final Duration TOKEN_TTL = Duration.ofMinutes(15);

    /** How long before a cached token expires that the next one is minted. */
    public static final Duration REFRESH_BEFORE = Duration.ofMinutes(2);

    private final String host;
    private final String region;
    private final AwsCredentialsProvider credentials;
    private final Clock clock;
    private String token;
    private Instant expires;

    /** Returns a TokenSource for the database at host, signing through the STS endpoint of region (null or empty for the global endpoint). */
    public TokenSource(String host, String region, AwsCredentialsProvider credentials) {
        this(host, region, credentials, Clock.systemUTC());
    }

    /** Same as the three-argument constructor, reading the current time from clock. */
    public TokenSource(String host, String region, AwsCredentialsProvider credentials, Clock clock) {
        this.host = host;
        this.region = region;
        this.credentials = credentials;
        this.clock = clock;
    }

    /** Returns the cached token, or mints a new one when it is missing or about to expire. */
    public synchronized String token() {
        Instant now = clock.instant();
        if (token != null && now.isBefore(expires.minus(REFRESH_BEFORE))) {
            return token;
        }
        if (credentials == null) {
            throw new IllegalArgumentException("dbauth: no AWS credentials provider");
        }
        AwsCredentialsIdentity identity = credentials.resolveCredentials();
        String minted = DbAuth.newToken(host, region, identity, now);
        Instant limit = now.plus(TOKEN_TTL);
        Instant credentialsExpire = identity.expirationTime().orElse(limit);
        expires = credentialsExpire.isBefore(limit) ? credentialsExpire : limit;
        token = minted;
        return token;
    }
}
