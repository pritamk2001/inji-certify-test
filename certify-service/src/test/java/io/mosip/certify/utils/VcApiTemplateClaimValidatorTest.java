/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class VcApiTemplateClaimValidatorTest {

    private static final String TEMPLATE_JSON = """
            {
              "docType": "${_doctype}",
              "validityInfo": {
                "validFrom": "${_validFrom}",
                "validUntil": "${_validUntil}"
              },
              "nameSpaces": {
                "org.iso.18013.5.1": [
                  { "digestID": 0, "elementIdentifier": "family_name", "elementValue": "${family_name}" },
                  { "digestID": 1, "elementIdentifier": "given_name",  "elementValue": "${given_name}" },
                  { "digestID": 2, "elementIdentifier": "birth_date",  "elementValue": "${birth_date}" }
                ]
              }
            }
            """;

    @Test
    public void extractRequiredClaimKeys_ignoresSystemPlaceholders() {
        String b64 = Base64.encodeBase64String(TEMPLATE_JSON.getBytes(StandardCharsets.UTF_8));

        Set<String> keys = VcApiTemplateClaimValidator.extractRequiredClaimKeys(b64);

        assertEquals(Set.of("family_name", "given_name", "birth_date"), keys);
        assertFalse(keys.contains("_doctype"));
        assertFalse(keys.contains("_validFrom"));
    }

    @Test
    public void validateRequiredClaims_success_whenAllPresent() {
        String b64 = Base64.encodeBase64String(TEMPLATE_JSON.getBytes(StandardCharsets.UTF_8));

        VcApiTemplateClaimValidator.validateRequiredClaims(b64, Map.of(
                "family_name", "Doe",
                "given_name", "Jane",
                "birth_date", "1990-01-15",
                "id", "did:jwk:abc"));
    }

    @Test
    public void validateRequiredClaims_throws_whenClaimMissing() {
        String b64 = Base64.encodeBase64String(TEMPLATE_JSON.getBytes(StandardCharsets.UTF_8));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> VcApiTemplateClaimValidator.validateRequiredClaims(b64, Map.of(
                        "family_name", "Doe",
                        "given_name", "Jane")));

        assertEquals(ErrorConstants.MISSING_MANDATORY_CLAIM, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("birth_date"));
    }

    @Test
    public void validateRequiredClaims_throws_whenClaimBlank() {
        String b64 = Base64.encodeBase64String(TEMPLATE_JSON.getBytes(StandardCharsets.UTF_8));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> VcApiTemplateClaimValidator.validateRequiredClaims(b64, Map.of(
                        "family_name", "Doe",
                        "given_name", "Jane",
                        "birth_date", "  ")));

        assertEquals(ErrorConstants.MISSING_MANDATORY_CLAIM, ex.getErrorCode());
    }

    @Test
    public void validateRequiredClaims_noop_whenTemplateBlank() {
        VcApiTemplateClaimValidator.validateRequiredClaims("", Map.of());
        VcApiTemplateClaimValidator.validateRequiredClaims(null, Map.of());
    }

    @Test
    public void extractRequiredClaimKeys_ignoresCertifyInjectedValidityDates() {
        String templateJson = """
                {
                  "issuer": "${_issuer}",
                  "validFrom": "${validFrom}",
                  "validUntil": "${validUntil}",
                  "issuanceDate": "${validFrom}",
                  "expirationDate": "${validUntil}",
                  "credentialSubject": {
                    "id": "${_holderId}",
                    "fullName": "${fullName}"
                  }
                }
                """;
        String b64 = Base64.encodeBase64String(templateJson.getBytes(StandardCharsets.UTF_8));

        Set<String> keys = VcApiTemplateClaimValidator.extractRequiredClaimKeys(b64);

        assertEquals(Set.of("fullName"), keys);
        assertFalse(keys.contains("validFrom"));
        assertFalse(keys.contains("validUntil"));
    }

    @Test
    public void validateRequiredClaims_success_forVcdm20TemplateWithoutValidityClaims() {
        String templateJson = """
                {
                  "validFrom": "${validFrom}",
                  "validUntil": "${validUntil}",
                  "credentialSubject": {
                    "fullName": "${fullName}"
                  }
                }
                """;
        String b64 = Base64.encodeBase64String(templateJson.getBytes(StandardCharsets.UTF_8));

        VcApiTemplateClaimValidator.validateRequiredClaims(b64, Map.of("fullName", "Jane Doe"));
    }
}
