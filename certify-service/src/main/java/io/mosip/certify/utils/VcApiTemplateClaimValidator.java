/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.exception.CertifyException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates that VC API {@code credentialSubject} supplies every claim placeholder
 * referenced by the onboarded {@code vcTemplate}.
 */
public final class VcApiTemplateClaimValidator {

    /**
     * Matches Velocity formal references: ${claim_name} or ${claim_name.nested}.
     * Only the top-level identifier is treated as a required claim key.
     */
    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)");

    private VcApiTemplateClaimValidator() {
    }

    /**
     * Extracts claim keys required by the template (excludes system placeholders that
     * Certify injects itself, e.g. {@code _doctype}, {@code _validFrom}, {@code validFrom}).
     */
    public static Set<String> extractRequiredClaimKeys(String base64VcTemplate) {
        if (StringUtils.isBlank(base64VcTemplate)) {
            return Set.of();
        }
        String templateJson = new String(Base64.decodeBase64(base64VcTemplate), StandardCharsets.UTF_8);
        Set<String> keys = new LinkedHashSet<>();
        Matcher matcher = PLACEHOLDER_PATTERN.matcher(templateJson);
        while (matcher.find()) {
            String key = matcher.group(1);
            if (!isSystemPlaceholder(key)) {
                keys.add(key);
            }
        }
        return keys;
    }

    /**
     * Fails if any template claim is missing or blank in {@code credentialSubject}.
     */
    public static void validateRequiredClaims(String base64VcTemplate, Map<String, Object> credentialSubject) {
        Set<String> required = extractRequiredClaimKeys(base64VcTemplate);
        if (required.isEmpty()) {
            return;
        }
        Map<String, Object> subject = credentialSubject != null ? credentialSubject : Map.of();
        List<String> missing = new ArrayList<>();
        for (String key : required) {
            if (!isPresentAndNonBlank(subject.get(key))) {
                missing.add(key);
            }
        }
        if (!missing.isEmpty()) {
            throw new CertifyException(ErrorConstants.MISSING_MANDATORY_CLAIM,
                    "Missing required claim(s) for vcTemplate: " + String.join(", ", missing));
        }
    }

    private static boolean isSystemPlaceholder(String key) {
        // Certify / Velocity injects these; clients must not supply them via credentialSubject.
        return key.startsWith("_")
                || VCDM2Constants.VALID_FROM.equals(key)
                || VCDM2Constants.VALID_UNTIL.equals(key)
                || "issuanceDate".equals(key)
                || "expirationDate".equals(key)
                || "rootContext".equals(key)
                || "envConfigs".equals(key)
                || "templateName".equals(key)
                || "DID_URL".equals(key)
                || "didUrl".equals(key);
    }

    private static boolean isPresentAndNonBlank(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof String str) {
            return StringUtils.isNotBlank(str);
        }
        return true;
    }
}
