/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds ISO/IEC 18013-5 aligned COSE_Sign1 (issuerAuth) using a local Document Signer key,
 * embedding the DS certificate in the unprotected {@code x5chain} header (label 33).
 */
@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class MdocLocalDsCoseSigner {

    private static final int COSE_ALG_LABEL = 1;
    private static final int COSE_ALG_ES256 = -7;
    private static final int COSE_X5CHAIN_LABEL = 33;
    private static final int ES256_COMPONENT_LENGTH = 32;
    private static final String SIG_CONTEXT = "Signature1";

    /**
     * Signs MSO CBOR bytes as COSE_Sign1 with ES256 and x5chain.
     *
     * @param msoCbor     CBOR-encoded Mobile Security Object (payload)
     * @param keyMaterial Document Signer private key + certificate
     * @return CBOR-encoded COSE_Sign1 bytes
     */
    public byte[] sign(byte[] msoCbor, MdocDsKeyMaterial keyMaterial) {
        try {
            byte[] protectedHeader = encodeProtectedHeader();
            Map unprotectedHeader = buildUnprotectedHeader(keyMaterial.certificate());
            byte[] toBeSigned = buildSigStructure(protectedHeader, msoCbor);
            byte[] signature = signEs256(toBeSigned, keyMaterial.privateKey());

            Array coseSign1 = new Array();
            coseSign1.add(new ByteString(protectedHeader));
            coseSign1.add(unprotectedHeader);
            coseSign1.add(new ByteString(msoCbor));
            coseSign1.add(new ByteString(signature));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(coseSign1);
            return baos.toByteArray();
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Local Document Signer COSE_Sign1 failed: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.MDOC_LOCAL_COSE_SIGN_FAILED,
                    "Failed to sign mDoc MSO with local Document Signer key");
        }
    }

    private static byte[] encodeProtectedHeader() throws Exception {
        Map protectedMap = new Map();
        protectedMap.put(new UnsignedInteger(COSE_ALG_LABEL), new NegativeInteger(COSE_ALG_ES256));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(protectedMap);
        return baos.toByteArray();
    }

    private static Map buildUnprotectedHeader(X509Certificate certificate) throws Exception {
        Map unprotected = new Map();
        Array x5chain = new Array();
        x5chain.add(new ByteString(certificate.getEncoded()));
        unprotected.put(new UnsignedInteger(COSE_X5CHAIN_LABEL), x5chain);
        return unprotected;
    }

    /**
     * Sig_structure = ["Signature1", protected, external_aad, payload]
     */
    private static byte[] buildSigStructure(byte[] protectedHeader, byte[] payload) throws Exception {
        Array sigStructure = new Array();
        sigStructure.add(new UnicodeString(SIG_CONTEXT));
        sigStructure.add(new ByteString(protectedHeader));
        sigStructure.add(new ByteString(new byte[0]));
        sigStructure.add(new ByteString(payload));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(sigStructure);
        return baos.toByteArray();
    }

    private static byte[] signEs256(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return derToConcatenated(signature.sign(), ES256_COMPONENT_LENGTH);
    }

    /**
     * Converts ASN.1 DER ECDSA signature to COSE concatenated r||s form.
     */
    static byte[] derToConcatenated(byte[] derSignature, int componentLength) throws Exception {
        ASN1Sequence sequence = ASN1Sequence.getInstance(derSignature);
        byte[] r = toFixedLength(((ASN1Integer) sequence.getObjectAt(0)).getValue(), componentLength);
        byte[] s = toFixedLength(((ASN1Integer) sequence.getObjectAt(1)).getValue(), componentLength);
        byte[] concatenated = new byte[componentLength * 2];
        System.arraycopy(r, 0, concatenated, 0, componentLength);
        System.arraycopy(s, 0, concatenated, componentLength, componentLength);
        return concatenated;
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[length];
        int srcPos = Math.max(0, raw.length - length);
        int destPos = Math.max(0, length - raw.length);
        int copyLen = Math.min(raw.length, length);
        System.arraycopy(raw, srcPos, result, destPos, copyLen);
        return result;
    }

    /**
     * Decodes COSE_Sign1 for tests / verification helpers.
     */
    public static List<DataItem> decodeCoseSign1(byte[] coseSign1) throws Exception {
        return new CborDecoder(new ByteArrayInputStream(coseSign1)).decode();
    }
}
