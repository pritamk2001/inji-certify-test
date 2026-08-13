package io.mosip.certify.utils;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.Locale;

public final class KeyManagerAppIdUtil {

    public static final int MAX_APP_ID_LENGTH = 36;
    private static final int HASH_LENGTH = 8;

    private KeyManagerAppIdUtil() {
    }

    public static String buildAppId(String prefix, String issuerId) {
        return buildAppId(prefix, issuerId, null);
    }

    public static String buildAppId(String prefix, String issuerId, String suffix) {
        String normalizedIssuerId = normalizeSegment(issuerId);
        String suffixPart = StringUtils.isBlank(suffix) ? "" : "_" + suffix;
        int availableLength = MAX_APP_ID_LENGTH - prefix.length() - suffixPart.length();

        if (availableLength <= 0) {
            throw new IllegalArgumentException("Prefix and suffix exceed KeyManager app id length limit");
        }
        if (normalizedIssuerId.length() <= availableLength) {
            return prefix + normalizedIssuerId + suffixPart;
        }

        String hash = DigestUtils.sha256Hex(StringUtils.defaultString(issuerId))
                .substring(0, HASH_LENGTH)
                .toUpperCase(Locale.ROOT);
        int stemLength = availableLength - HASH_LENGTH - 1;
        if (stemLength <= 0) {
            return prefix + hash.substring(0, availableLength) + suffixPart;
        }

        String stem = StringUtils.stripEnd(normalizedIssuerId.substring(0, stemLength), "_");
        if (stem.isEmpty()) {
            return prefix + hash.substring(0, availableLength) + suffixPart;
        }
        return prefix + stem + "_" + hash + suffixPart;
    }

    private static String normalizeSegment(String value) {
        String normalized = StringUtils.defaultString(value)
                .toUpperCase(Locale.ROOT)
                .replaceAll("[^A-Z0-9]+", "_");
        normalized = StringUtils.strip(normalized, "_");
        return normalized.isEmpty() ? "ISSUER" : normalized;
    }
}
