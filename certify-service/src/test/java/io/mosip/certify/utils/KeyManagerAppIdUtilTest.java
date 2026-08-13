package io.mosip.certify.utils;

import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.validation.IssuerIdValidator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyManagerAppIdUtilTest {

    @Test
    void buildAppId_keepsReadableShortIssuerIds() {
        String appId = KeyManagerAppIdUtil.buildAppId(IssuerConstants.KEY_APP_ID_PREFIX, "farmer", "ED25519");

        assertEquals("CERTIFY_ISSUER_FARMER_ED25519", appId);
    }

    @Test
    void buildAppId_shortensLongIssuerIdsDeterministically() {
        String issuerId = "CERTIFY_ISSUER_SURRAO_E9561EFC_ED25519";

        String appId = KeyManagerAppIdUtil.buildAppId(IssuerConstants.KEY_APP_ID_PREFIX, issuerId, "ED25519");
        String sameAppId = KeyManagerAppIdUtil.buildAppId(IssuerConstants.KEY_APP_ID_PREFIX, issuerId, "ED25519");

        assertEquals(appId, sameAppId);
        assertEquals(KeyManagerAppIdUtil.MAX_APP_ID_LENGTH, appId.length());
        assertTrue(appId.startsWith(IssuerConstants.KEY_APP_ID_PREFIX));
        assertTrue(appId.endsWith("_ED25519"));
    }

    @Test
    void buildAppId_normalizesDidStyleIssuerIds() {
        String issuerId = "did:web:sample.github.io:my-files:sample";

        String appId = KeyManagerAppIdUtil.buildAppId(IssuerConstants.IACA_APP_ID_PREFIX, issuerId);

        assertEquals(KeyManagerAppIdUtil.MAX_APP_ID_LENGTH, appId.length());
        assertTrue(appId.startsWith(IssuerConstants.IACA_APP_ID_PREFIX));
        assertTrue(appId.contains("DID_WEB"));
    }

    @Test
    void issuerIdPattern_allowsDidStyleIssuerIds() {
        assertTrue(IssuerIdValidator.isValid("did:web:sample.github.io:my-files:sample"));
    }

    @Test
    void issuerIdPattern_allowsTrimmedAndUnderscoreBoundedIds() {
        assertTrue(IssuerIdValidator.isValid(" surrao-e9561efc "));
        assertTrue(IssuerIdValidator.isValid("_surrao"));
        assertTrue(IssuerIdValidator.isValid("surrao_e9561efc_"));
        assertEquals("surrao-e9561efc", IssuerIdValidator.normalize(" surrao-e9561efc "));
    }

    @Test
    void issuerIdPattern_rejectsUrlsAndSlashes() {
        assertFalse(IssuerIdValidator.isValid("https://collectible-dissentiently-arie.ngrok-free.dev/v1/certify"));
        assertFalse(IssuerIdValidator.isValid("surrao/e9561efc"));
    }
}
