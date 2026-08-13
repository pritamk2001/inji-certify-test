package io.mosip.certify.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DidWebUtilTest {

    @Test
    void buildIssuerDidWebIdentifier_includesServletPath() {
        String did = DidWebUtil.buildIssuerDidWebIdentifier(
                "https://example.com", "/v1/certify", "iiitb");
        assertEquals("did:web:example.com:v1:certify:issuers:iiitb", did);
    }

    @Test
    void buildIssuerDidDocumentUrl_matchesDidWebResolution() {
        String url = DidWebUtil.buildIssuerDidDocumentUrl(
                "https://example.com", "/v1/certify", "iiitb");
        assertEquals("https://example.com/v1/certify/issuers/iiitb/did.json", url);
    }

    @Test
    void buildIssuerDidWebIdentifier_withoutServletPath() {
        String did = DidWebUtil.buildIssuerDidWebIdentifier(
                "https://example.com", "", "iiitb");
        assertEquals("did:web:example.com:issuers:iiitb", did);
    }
}
