/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Loads Document Signer key material from
 * {@code mosip.certify.mdoc.issuer-key-cert} (preferred) or
 * {@code mosip.certify.mock.mdoc.issuer-key-cert} (fallback).
 * <p>
 * Expected format: {@code base64(PKCS8 private key DER)||base64(X.509 cert PEM or DER)}.
 */
@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class MdocIssuerKeyCertLoader {

    @Value("${mosip.certify.mdoc.issuer-key-cert:}")
    private String primaryIssuerKeyCert;

    @Value("${mosip.certify.mock.mdoc.issuer-key-cert:}")
    private String mockIssuerKeyCert;

    public MdocDsKeyMaterial load() {
        String raw = resolveConfiguredValue();
        if (StringUtils.isBlank(raw)) {
            throw new CertifyException(ErrorConstants.MDOC_DS_KEY_NOT_CONFIGURED,
                    "Document Signer key/cert is not configured. Set mosip.certify.mdoc.issuer-key-cert "
                            + "or mosip.certify.mock.mdoc.issuer-key-cert "
                            + "(format: base64PrivateKey||base64Certificate)");
        }

        String[] parts = raw.split("\\|\\|", 2);
        if (parts.length != 2 || StringUtils.isBlank(parts[0]) || StringUtils.isBlank(parts[1])) {
            throw new CertifyException(ErrorConstants.MDOC_DS_KEY_INVALID,
                    "Invalid Document Signer key/cert format. Expected base64PrivateKey||base64Certificate");
        }

        try {
            byte[] keyBytes = Base64.getDecoder().decode(parts[0].trim());
            byte[] certBytes = Base64.getDecoder().decode(parts[1].trim());

            PrivateKey privateKey = KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(certBytes));

            return new MdocDsKeyMaterial(privateKey, certificate);
        } catch (CertifyException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            log.error("Failed to decode Document Signer key/cert base64: {}", e.getMessage());
            throw new CertifyException(ErrorConstants.MDOC_DS_KEY_INVALID,
                    "Document Signer key/cert is not valid Base64");
        } catch (Exception e) {
            log.error("Failed to parse Document Signer key/cert: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.MDOC_DS_KEY_INVALID,
                    "Failed to parse Document Signer private key or certificate");
        }
    }

    private String resolveConfiguredValue() {
        if (StringUtils.isNotBlank(primaryIssuerKeyCert)) {
            return primaryIssuerKeyCert.trim();
        }
        if (StringUtils.isNotBlank(mockIssuerKeyCert)) {
            return mockIssuerKeyCert.trim();
        }
        return null;
    }
}
