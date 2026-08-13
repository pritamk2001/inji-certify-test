/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class MdocLocalDsCoseSignerTest {

    private MdocLocalDsCoseSigner signer;
    private MdocDsKeyMaterial keyMaterial;

    @BeforeClass
    public static void addProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Before
    public void setUp() throws Exception {
        signer = new MdocLocalDsCoseSigner();
        String property = MdocIssuerKeyCertLoaderTest.generateKeyCertProperty();
        String[] parts = property.split("\\|\\|", 2);
        var privateKey = KeyFactory.getInstance("EC")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(Base64.getDecoder().decode(parts[0])));
        X509Certificate certificate = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(parts[1])));
        keyMaterial = new MdocDsKeyMaterial(privateKey, certificate);
    }

    @Test
    public void sign_producesCoseSign1WithX5chain() throws Exception {
        byte[] payload = "test-mso-payload".getBytes();

        byte[] coseBytes = signer.sign(payload, keyMaterial);

        List<DataItem> decoded = MdocLocalDsCoseSigner.decodeCoseSign1(coseBytes);
        assertEquals(1, decoded.size());
        Array coseSign1 = (Array) decoded.get(0);
        assertEquals(4, coseSign1.getDataItems().size());

        ByteString protectedHeader = (ByteString) coseSign1.getDataItems().get(0);
        assertTrue(protectedHeader.getBytes().length > 0);

        Map unprotected = (Map) coseSign1.getDataItems().get(1);
        DataItem x5chain = unprotected.get(new UnsignedInteger(33));
        assertNotNull(x5chain);
        assertTrue(x5chain instanceof Array);
        ByteString certBytes = (ByteString) ((Array) x5chain).getDataItems().get(0);
        assertEquals(Base64.getEncoder().encodeToString(keyMaterial.certificate().getEncoded()),
                Base64.getEncoder().encodeToString(certBytes.getBytes()));

        ByteString payloadItem = (ByteString) coseSign1.getDataItems().get(2);
        assertEquals(new String(payload), new String(payloadItem.getBytes()));

        ByteString signatureItem = (ByteString) coseSign1.getDataItems().get(3);
        assertEquals(64, signatureItem.getBytes().length);
    }

    @Test
    public void sign_signatureVerifiesWithPublicKey() throws Exception {
        byte[] payload = new byte[]{1, 2, 3, 4, 5};
        byte[] coseBytes = signer.sign(payload, keyMaterial);

        Array coseSign1 = (Array) MdocLocalDsCoseSigner.decodeCoseSign1(coseBytes).get(0);
        byte[] protectedHeader = ((ByteString) coseSign1.getDataItems().get(0)).getBytes();
        byte[] cosePayload = ((ByteString) coseSign1.getDataItems().get(2)).getBytes();
        byte[] signature = ((ByteString) coseSign1.getDataItems().get(3)).getBytes();

        byte[] sigStructure = buildSigStructure(protectedHeader, cosePayload);
        byte[] derSignature = concatenatedToDer(signature);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(keyMaterial.certificate().getPublicKey());
        verifier.update(sigStructure);
        assertTrue(verifier.verify(derSignature));
    }

    @Test
    public void derToConcatenated_roundTripLength() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(kp.getPrivate());
        signature.update("hello".getBytes());
        byte[] der = signature.sign();

        byte[] concatenated = MdocLocalDsCoseSigner.derToConcatenated(der, 32);
        assertEquals(64, concatenated.length);
    }

    private static byte[] buildSigStructure(byte[] protectedHeader, byte[] payload) throws Exception {
        Array sigStructure = new Array();
        sigStructure.add(new co.nstant.in.cbor.model.UnicodeString("Signature1"));
        sigStructure.add(new ByteString(protectedHeader));
        sigStructure.add(new ByteString(new byte[0]));
        sigStructure.add(new ByteString(payload));
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        new co.nstant.in.cbor.CborEncoder(baos).encode(sigStructure);
        return baos.toByteArray();
    }

    private static byte[] concatenatedToDer(byte[] concatenated) throws Exception {
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(concatenated, 0, r, 0, 32);
        System.arraycopy(concatenated, 32, s, 0, 32);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(new BigInteger(1, r)));
        vector.add(new ASN1Integer(new BigInteger(1, s)));
        return new DERSequence(vector).getEncoded();
    }
}
