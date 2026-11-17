package sh.userelay.dbauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

class TokenSourceTest {
    private static final String HOST = "orders.db.userelay.sh";
    private static final Instant START = Instant.parse("2026-01-02T03:04:05Z");

    private static final class Ticking extends Clock {
        private Instant now = START;

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @Test
    void constants() {
        assertEquals(Duration.ofMinutes(15), TokenSource.TOKEN_TTL);
        assertEquals(Duration.ofMinutes(2), TokenSource.REFRESH_BEFORE);
    }

    @Test
    void usesTheSystemClockByDefault() {
        TokenSource source = new TokenSource(HOST, "us-east-1", DbAuthTest.provider("AKIDJAVA6", ""));
        assertEquals(source.token(), source.token());
    }

    @Test
    void cachesUntilTwoMinutesBeforeExpiry() {
        Ticking clock = new Ticking();
        AtomicInteger calls = new AtomicInteger();
        AwsCredentialsProvider counting = () -> {
            calls.incrementAndGet();
            return AwsSessionCredentials.create("AKIDJAVA7", "secret", "t");
        };
        TokenSource source = new TokenSource(HOST, "", counting, clock);
        String first = source.token();
        clock.advance(Duration.ofMinutes(12).plusSeconds(59));
        assertEquals(first, source.token());
        assertEquals(1, calls.get());
        clock.advance(Duration.ofSeconds(1));
        assertNotEquals(first, source.token());
        assertEquals(2, calls.get());
    }

    @Test
    void expiresWithTheCredentialsWhenTheyDoSooner() {
        Ticking clock = new Ticking();
        AtomicInteger calls = new AtomicInteger();
        AwsCredentialsProvider shortLived = () -> {
            calls.incrementAndGet();
            return AwsSessionCredentials.builder().accessKeyId("AKIDJAVA8").secretAccessKey("secret").sessionToken("t")
                    .expirationTime(clock.instant().plus(Duration.ofMinutes(5))).build();
        };
        TokenSource source = new TokenSource(HOST, "", shortLived, clock);
        source.token();
        clock.advance(Duration.ofMinutes(2));
        source.token();
        assertEquals(1, calls.get());
        clock.advance(Duration.ofMinutes(1));
        source.token();
        assertEquals(2, calls.get());
    }

    @Test
    void ignoresCredentialExpiryBeyondTheTokenTtl() {
        Ticking clock = new Ticking();
        AtomicInteger calls = new AtomicInteger();
        AwsCredentialsProvider longLived = () -> {
            calls.incrementAndGet();
            return AwsSessionCredentials.builder().accessKeyId("AKIDJAVA9").secretAccessKey("secret").sessionToken("t")
                    .expirationTime(clock.instant().plus(Duration.ofHours(6))).build();
        };
        TokenSource source = new TokenSource(HOST, "", longLived, clock);
        source.token();
        clock.advance(Duration.ofMinutes(13));
        source.token();
        assertEquals(2, calls.get());
    }

    @Test
    void refusesWithoutCredentials() {
        TokenSource source = new TokenSource(HOST, "", null, new Ticking());
        assertTrue(assertThrows(IllegalArgumentException.class, source::token).getMessage().contains("no AWS credentials provider"));
    }

    @Test
    void doesNotCacheAFailure() {
        TokenSource source = new TokenSource("localhost", "", DbAuthTest.provider("AKIDJAVAA", ""), new Ticking());
        assertThrows(IllegalArgumentException.class, source::token);
        assertThrows(IllegalArgumentException.class, source::token);
    }
}
