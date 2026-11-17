package sh.relay.dbauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

class DbAuthTest {
    private static final Instant NOW = Instant.parse("2026-01-02T03:04:05Z");

    @AfterEach
    void restoreAlgorithms() {
        DbAuth.digestAlgorithm = "SHA-256";
        DbAuth.hmacAlgorithm = "HmacSHA256";
    }

    static List<JsonNode> vectors() throws IOException {
        List<JsonNode> out = new ArrayList<>();
        new ObjectMapper().readTree(new File("../testvectors/tokens.json")).forEach(out::add);
        return out;
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void matchesTheSharedVectors(JsonNode v) {
        AwsCredentialsProvider provider = StaticCredentialsProvider.create(v.has("sessionToken")
                ? AwsSessionCredentials.create(v.get("accessKeyId").asText(), v.get("secretAccessKey").asText(), v.get("sessionToken").asText())
                : AwsBasicCredentials.create(v.get("accessKeyId").asText(), v.get("secretAccessKey").asText()));
        String region = v.has("region") ? v.get("region").asText() : null;
        assertEquals(v.get("token").asText(), DbAuth.newToken(v.get("host").asText(), region, provider, Instant.parse(v.get("time").asText())));
    }

    @Test
    void mintsWithTheCurrentTime() {
        String token = DbAuth.newToken("Orders.AB1CD.db.userelay.sh", "us-east-1", provider("AKIDJAVA1", ""));
        assertTrue(token.startsWith("sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&"));
        assertTrue(token.endsWith("&X-Relay-Server-Id=orders.ab1cd.db.userelay.sh"));
        assertTrue(token.contains("X-Amz-SignedHeaders=host%3Bx-relay-server-id"));
    }

    @Test
    void emptyRegionIsTheGlobalEndpoint() {
        String token = DbAuth.newToken("orders.db.userelay.sh", "", provider("AKIDJAVA2", ""), NOW);
        assertTrue(token.startsWith("sts.amazonaws.com/?"));
        assertTrue(token.contains("%2Fus-east-1%2Fsts%2Faws4_request"));
    }

    @Test
    void encodesEveryReservedCharacterOfTheSessionToken() {
        String token = DbAuth.newToken("orders.db.userelay.sh", null, provider("AKIDJAVA3", "Az09-_.~ +/=!é"), NOW);
        assertTrue(token.contains("X-Amz-Security-Token=Az09-_.~%20%2B%2F%3D%21%C3%A9&"));
    }

    @Test
    void refusesBadInput() {
        AwsCredentialsProvider ok = provider("AKIDJAVA4", "");
        AwsCredentialsProvider none = null;
        assertRefused("no AWS credentials provider", () -> DbAuth.newToken("orders.db.userelay.sh", "", none, NOW));
        assertRefused("without a port", () -> DbAuth.newToken("orders.db.userelay.sh:5432", "", ok, NOW));
        assertRefused("not a database hostname", () -> DbAuth.newToken(null, "", ok, NOW));
        assertRefused("not a database hostname", () -> DbAuth.newToken("", "", ok, NOW));
        assertRefused("not a database hostname", () -> DbAuth.newToken("localhost", "", ok, NOW));
        assertRefused("not a database hostname", () -> DbAuth.newToken("postgres://orders.db.userelay.sh", "", ok, NOW));
        assertRefused("invalid region", () -> DbAuth.newToken("orders.db.userelay.sh", "us-east", ok, NOW));
    }

    @Test
    void reportsUnavailableAlgorithms() {
        AwsCredentialsProvider ok = provider("AKIDJAVA5", "");
        DbAuth.digestAlgorithm = "none";
        assertThrows(IllegalStateException.class, () -> DbAuth.newToken("orders.db.userelay.sh", "", ok, NOW));
        DbAuth.digestAlgorithm = "SHA-256";
        DbAuth.hmacAlgorithm = "none";
        assertThrows(IllegalStateException.class, () -> DbAuth.newToken("orders.db.userelay.sh", "", ok, NOW));
    }

    private static void assertRefused(String message, Executable call) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, call);
        assertTrue(e.getMessage().contains(message), e.getMessage());
    }

    static AwsCredentialsProvider provider(String keyId, String sessionToken) {
        return StaticCredentialsProvider.create(sessionToken.isEmpty()
                ? AwsBasicCredentials.create(keyId, "secret")
                : AwsSessionCredentials.create(keyId, "secret", sessionToken));
    }
}
