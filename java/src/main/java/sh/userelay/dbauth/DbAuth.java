package sh.userelay.dbauth;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.identity.spi.AwsSessionCredentialsIdentity;

/** Mints the IAM tokens that log in to Relay databases. */
public final class DbAuth {
    private static final String SERVER_ID_HEADER = "X-Relay-Server-Id";
    private static final String GLOBAL_HOST = "sts.amazonaws.com";
    private static final String GLOBAL_REGION = "us-east-1";
    private static final String EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private static final Pattern AWS_REGION = Pattern.compile("[a-z]{2}(-[a-z]+)+-[0-9]");
    private static final Pattern DB_HOST = Pattern.compile("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+");
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static final String UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

    static volatile String digestAlgorithm = "SHA-256";
    static volatile String hmacAlgorithm = "HmacSHA256";

    private DbAuth() {
    }

    /** Returns a token for the database at host, signed through the STS endpoint of region (null or empty for the global endpoint). */
    public static String newToken(String host, String region, AwsCredentialsProvider credentials) {
        return newToken(host, region, credentials, Instant.now());
    }

    static String newToken(String host, String region, AwsCredentialsProvider credentials, Instant now) {
        if (credentials == null) {
            throw new IllegalArgumentException("dbauth: no AWS credentials provider");
        }
        return newToken(host, region, credentials.resolveCredentials(), now);
    }

    static String newToken(String host, String region, AwsCredentialsIdentity credentials, Instant now) {
        String lowerHost = host == null ? "" : host.toLowerCase(Locale.ROOT);
        if (!DB_HOST.matcher(lowerHost).matches()) {
            throw new IllegalArgumentException("dbauth: \"" + lowerHost + "\" is not a database hostname; pass the host from the connection string without a port");
        }
        String stsHost = GLOBAL_HOST;
        String signingRegion = GLOBAL_REGION;
        if (region != null && !region.isEmpty()) {
            if (!AWS_REGION.matcher(region).matches()) {
                throw new IllegalArgumentException("dbauth: invalid region \"" + region + "\"");
            }
            stsHost = regionalHost(region);
            signingRegion = region;
        }

        String date = DATE.format(now);
        String credentialScope = date + "/" + signingRegion + "/sts/aws4_request";
        StringBuilder query = new StringBuilder("Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256");
        query.append("&X-Amz-Credential=").append(encode(credentials.accessKeyId() + "/" + credentialScope));
        query.append("&X-Amz-Date=").append(TIMESTAMP.format(now));
        query.append("&X-Amz-Expires=").append(TokenSource.TOKEN_TTL.getSeconds());
        if (credentials instanceof AwsSessionCredentialsIdentity) {
            query.append("&X-Amz-Security-Token=").append(encode(((AwsSessionCredentialsIdentity) credentials).sessionToken()));
        }
        query.append("&X-Amz-SignedHeaders=host%3Bx-relay-server-id");

        String canonicalRequest = "GET\n/\n" + query + "\nhost:" + stsHost + "\nx-relay-server-id:" + lowerHost
                + "\n\nhost;x-relay-server-id\n" + EMPTY_PAYLOAD_HASH;
        String stringToSign = "AWS4-HMAC-SHA256\n" + TIMESTAMP.format(now) + "\n" + credentialScope + "\n" + hex(sha256(canonicalRequest));

        byte[] key = hmac(("AWS4" + credentials.secretAccessKey()).getBytes(StandardCharsets.UTF_8), date);
        key = hmac(key, signingRegion);
        key = hmac(key, "sts");
        key = hmac(key, "aws4_request");
        String signature = hex(hmac(key, stringToSign));

        return stsHost + "/?" + query + "&X-Amz-Signature=" + signature + "&" + SERVER_ID_HEADER + "=" + encode(lowerHost);
    }

    private static String regionalHost(String region) {
        return "sts." + region + (region.startsWith("cn-") ? ".amazonaws.com.cn" : ".amazonaws.com");
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance(digestAlgorithm).digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(new SecretKeySpec(key, hmacAlgorithm));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[2 * i] = HEX[(bytes[i] >> 4) & 0xf];
            out[2 * i + 1] = HEX[bytes[i] & 0xf];
        }
        return new String(out);
    }

    private static String encode(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if (UNRESERVED.indexOf(c) >= 0) {
                out.append(c);
            } else {
                out.append('%').append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16))).append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return out.toString();
    }
}
