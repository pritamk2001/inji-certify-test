/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;

/**
 * Builds IACA (CA) and Document Signer (end-entity) X.509 certificates for mdoc PKI.
 */
final class MdocCertificateFactory {

    private static final String SIGN_ALGORITHM = "SHA256withECDSA";

    private MdocCertificateFactory() {
    }

    static X509Certificate buildIacaCertificate(
            PrivateKey iacaPrivateKey,
            PublicKey iacaPublicKey,
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName) throws Exception {
        X500Name subject = buildDn(commonName, organization, organizationalUnit, country, state, location);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign);
        return buildCertificate(
                iacaPrivateKey,
                iacaPublicKey,
                subject,
                subject,
                keyUsage,
                new BasicConstraints(true),
                notBefore,
                notAfter,
                providerName);
    }

    static X509Certificate buildDsCertificate(
            PrivateKey iacaPrivateKey,
            PublicKey dsPublicKey,
            X500Name iacaSubject,
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName) throws Exception {
        X500Name subject = buildDn(commonName, organization, organizationalUnit, country, state, location);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);
        return buildCertificate(
                iacaPrivateKey,
                dsPublicKey,
                iacaSubject,
                subject,
                keyUsage,
                new BasicConstraints(false),
                notBefore,
                notAfter,
                providerName);
    }

    static String toPem(X509Certificate certificate) throws Exception {
        String encoded = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----";
    }

    static X500Name toX500Name(X509Certificate certificate) {
        return new X500Name(RFC4519Style.INSTANCE, certificate.getSubjectX500Principal().getName());
    }

    private static X509Certificate buildCertificate(
            PrivateKey signPrivateKey,
            PublicKey publicKey,
            X500Name issuer,
            X500Name subject,
            KeyUsage keyUsage,
            BasicConstraints basicConstraints,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName) throws Exception {
        BigInteger serial = new BigInteger(64, new SecureRandom()).abs();
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGN_ALGORITHM);
        if (providerName != null && !providerName.isBlank()) {
            signerBuilder.setProvider(providerName);
        }
        ContentSigner contentSigner = signerBuilder.build(signPrivateKey);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                toDate(notBefore),
                toDate(notAfter),
                subject,
                publicKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        X509CertificateHolder holder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static X500Name buildDn(
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location) {
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
        addRdn(builder, BCStyle.C, country);
        addRdn(builder, BCStyle.ST, state);
        addRdn(builder, BCStyle.L, location);
        addRdn(builder, BCStyle.O, organization);
        addRdn(builder, BCStyle.OU, organizationalUnit);
        addRdn(builder, BCStyle.CN, commonName);
        return builder.build();
    }

    private static void addRdn(X500NameBuilder builder, org.bouncycastle.asn1.ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.isBlank()) {
            builder.addRDN(oid, value);
        }
    }

    private static Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.toInstant(ZoneOffset.UTC));
    }
}
