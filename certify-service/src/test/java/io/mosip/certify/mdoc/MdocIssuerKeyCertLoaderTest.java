/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

public class MdocIssuerKeyCertLoaderTest {

    private MdocIssuerKeyCertLoader loader;
    private String validKeyCertValue;

    @BeforeClass
    public static void addProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Before
    public void setUp() throws Exception {
        loader = new MdocIssuerKeyCertLoader();
        validKeyCertValue = generateKeyCertProperty();
        ReflectionTestUtils.setField(loader, "primaryIssuerKeyCert", "");
        ReflectionTestUtils.setField(loader, "mockIssuerKeyCert", "");
    }

    @Test
    public void load_success_fromPrimaryProperty() {
        ReflectionTestUtils.setField(loader, "primaryIssuerKeyCert", validKeyCertValue);

        MdocDsKeyMaterial material = loader.load();

        assertNotNull(material.privateKey());
        assertNotNull(material.certificate());
        assertEquals("EC", material.privateKey().getAlgorithm());
    }

    @Test
    public void load_success_fromMockFallbackProperty() {
        ReflectionTestUtils.setField(loader, "mockIssuerKeyCert", validKeyCertValue);

        MdocDsKeyMaterial material = loader.load();

        assertNotNull(material.privateKey());
        assertNotNull(material.certificate());
    }

    @Test
    public void load_prefersPrimaryOverMock() throws Exception {
        ReflectionTestUtils.setField(loader, "primaryIssuerKeyCert", validKeyCertValue);
        ReflectionTestUtils.setField(loader, "mockIssuerKeyCert", "invalid||value");

        MdocDsKeyMaterial material = loader.load();
        assertNotNull(material.privateKey());
    }

    @Test
    public void load_throws_whenNotConfigured() {
        CertifyException ex = assertThrows(CertifyException.class, () -> loader.load());
        assertEquals(ErrorConstants.MDOC_DS_KEY_NOT_CONFIGURED, ex.getErrorCode());
    }

    @Test
    public void load_throws_whenMissingSeparator() {
        ReflectionTestUtils.setField(loader, "primaryIssuerKeyCert", "only-one-part");

        CertifyException ex = assertThrows(CertifyException.class, () -> loader.load());
        assertEquals(ErrorConstants.MDOC_DS_KEY_INVALID, ex.getErrorCode());
    }

    @Test
    public void load_throws_whenInvalidBase64() {
        ReflectionTestUtils.setField(loader, "primaryIssuerKeyCert", "!!!||???");

        CertifyException ex = assertThrows(CertifyException.class, () -> loader.load());
        assertEquals(ErrorConstants.MDOC_DS_KEY_INVALID, ex.getErrorCode());
    }

    static String generateKeyCertProperty() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name("CN=Test DS,O=Inji,C=IN");
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));

        String keyB64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String certB64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
        return keyB64 + "||" + certB64;
    }
}
