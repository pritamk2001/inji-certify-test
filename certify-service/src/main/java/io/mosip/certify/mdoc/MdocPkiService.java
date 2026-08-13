/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.utils.KeyManagerAppIdUtil;
import io.mosip.kernel.core.keymanager.model.CertificateEntry;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.repository.KeyPolicyRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * Provisions and rotates mdoc IACA / Document Signer material via MOSIP KeyManager.
 */
@Slf4j
@Service
public class MdocPkiService {

    private static final String CREATED_BY = "certify-mdoc-pki";

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyPolicyRepository keyPolicyRepository;

    @Value("${mosip.certify.mdoc.iaca.key-policy.validity-days:7300}")
    private int iacaValidityDays;

    @Value("${mosip.certify.mdoc.iaca.key-policy.pre-expire-days:90}")
    private int iacaPreExpireDays;

    @Value("${mosip.certify.mdoc.ds.key-policy.validity-days:730}")
    private int dsValidityDays;

    @Value("${mosip.certify.mdoc.ds.key-policy.pre-expire-days:60}")
    private int dsPreExpireDays;

    @Value("${mosip.certify.mdoc.iaca.certificate.common-name-prefix:IACA-}")
    private String iacaCnPrefix;

    @Value("${mosip.certify.mdoc.ds.certificate.common-name-prefix:DS-}")
    private String dsCnPrefix;

    @Value("${mosip.certify.mdoc.certificate.organization:${mosip.kernel.keymanager.certificate.default.organization:MOSIP}}")
    private String organization;

    @Value("${mosip.certify.mdoc.certificate.organizational-unit:${mosip.kernel.keymanager.certificate.default.organizational-unit:CERTIFY}}")
    private String organizationalUnit;

    @Value("${mosip.certify.mdoc.certificate.country:${mosip.kernel.keymanager.certificate.default.country:IN}}")
    private String country;

    @Value("${mosip.certify.mdoc.certificate.state:${mosip.kernel.keymanager.certificate.default.state:}}")
    private String state;

    @Value("${mosip.certify.mdoc.certificate.location:${mosip.kernel.keymanager.certificate.default.location:}}")
    private String location;

    /**
     * Creates IACA + DS EC P-256 keys, rebuilds IACA→DS certificate chain, uploads to KeyManager.
     */
    public MdocPkiRefs provision(String issuerId) {
        String iacaAppId = buildAppId(IssuerConstants.IACA_APP_ID_PREFIX, issuerId);
        String dsAppId = buildAppId(IssuerConstants.DS_APP_ID_PREFIX, issuerId);
        String refId = Constants.EC_SECP256R1_SIGN;

        try {
            ensureKeyPolicy(iacaAppId, iacaValidityDays, iacaPreExpireDays);
            ensureKeyPolicy(dsAppId, dsValidityDays, dsPreExpireDays);

            generateEcSignKey(iacaAppId, refId, false);
            generateEcSignKey(dsAppId, refId, false);

            X509Certificate iacaCert = rebuildAndUploadIaca(iacaAppId, refId, issuerId);
            rebuildAndUploadDs(iacaAppId, dsAppId, refId, issuerId, iacaCert);

            log.info("Provisioned mdoc IACA/DS keys for issuer {} (iaca={}, ds={})", issuerId, iacaAppId, dsAppId);
            return new MdocPkiRefs(iacaAppId, refId, dsAppId, refId);
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to provision mdoc IACA/DS for issuer {}", issuerId, e);
            throw new CertifyException(ErrorConstants.MDOC_PKI_PROVISIONING_FAILED,
                    "Failed to provision mdoc IACA/DS keys for issuer: " + issuerId);
        }
    }

    /**
     * Force-rotates Document Signer keypair and re-signs DS certificate with existing IACA.
     */
    public void rotateDocumentSigner(Issuer issuer) {
        if (issuer == null
                || StringUtils.isBlank(issuer.getMdocIacaAppId())
                || StringUtils.isBlank(issuer.getMdocDsAppId())) {
            throw new CertifyException(ErrorConstants.MDOC_DS_ROTATION_FAILED,
                    "Issuer is missing mdoc IACA/DS KeyManager references");
        }
        String iacaAppId = issuer.getMdocIacaAppId();
        String dsAppId = issuer.getMdocDsAppId();
        String iacaRefId = StringUtils.defaultIfBlank(issuer.getMdocIacaRefId(), Constants.EC_SECP256R1_SIGN);
        String dsRefId = StringUtils.defaultIfBlank(issuer.getMdocDsRefId(), Constants.EC_SECP256R1_SIGN);

        try {
            generateEcSignKey(dsAppId, dsRefId, true);
            SignatureCertificate iacaMaterial = loadSignatureCertificate(iacaAppId, iacaRefId);
            X509Certificate iacaCert = iacaMaterial.getCertificateEntry().getChain()[0];
            rebuildAndUploadDs(iacaAppId, dsAppId, iacaRefId, dsRefId, issuer.getIssuerId(), iacaCert);
            log.info("Rotated mdoc Document Signer for issuer {}", issuer.getIssuerId());
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to rotate mdoc DS for issuer {}", issuer.getIssuerId(), e);
            throw new CertifyException(ErrorConstants.MDOC_DS_ROTATION_FAILED,
                    "Failed to rotate mdoc Document Signer for issuer: " + issuer.getIssuerId());
        }
    }

    /**
     * Returns true when the current DS certificate is missing, expired, or within pre-expire window.
     */
    public boolean isDsRotationDue(Issuer issuer) {
        if (issuer == null || StringUtils.isBlank(issuer.getMdocDsAppId())) {
            return false;
        }
        String refId = StringUtils.defaultIfBlank(issuer.getMdocDsRefId(), Constants.EC_SECP256R1_SIGN);
        try {
            X509Certificate dsCert = loadCertificate(issuer.getMdocDsAppId(), refId);
            LocalDateTime notAfter = LocalDateTime.ofInstant(dsCert.getNotAfter().toInstant(), ZoneOffset.UTC);
            LocalDateTime rotateAfter = notAfter.minusDays(dsPreExpireDays);
            return !LocalDateTime.now(ZoneOffset.UTC).isBefore(rotateAfter);
        } catch (Exception e) {
            log.warn("Unable to read DS certificate for issuer {}; treating as rotation due: {}",
                    issuer.getIssuerId(), e.getMessage());
            return true;
        }
    }

    /**
     * On-demand DS rotation (ROOT-style): if the Document Signer is within the pre-expire window
     * or past expiry, force-rotate and re-sign the DS certificate with the existing IACA before use.
     * Does nothing when rotation is not due.
     */
    public void ensureDocumentSignerCurrent(Issuer issuer) {
        if (!isDsRotationDue(issuer)) {
            return;
        }
        log.info("Document Signer near expiry/expired for issuer {}; rotating on demand",
                issuer != null ? issuer.getIssuerId() : "null");
        rotateDocumentSigner(issuer);
    }

    public int getDsPreExpireDays() {
        return dsPreExpireDays;
    }

    public int getIacaValidityDays() {
        return iacaValidityDays;
    }

    public int getDsValidityDays() {
        return dsValidityDays;
    }

    /**
     * Exports the issuer IACA root certificate as PEM for verifier trust-store installation
     * (ISO/IEC 18013-5 out-of-band IACA dissemination).
     */
    public String exportIacaCertificatePem(Issuer issuer) {
        if (issuer == null
                || StringUtils.isBlank(issuer.getMdocIacaAppId())) {
            throw new CertifyException(ErrorConstants.MDOC_IACA_NOT_CONFIGURED,
                    "Issuer is missing mdoc IACA KeyManager references; cannot export trust anchor");
        }
        String iacaAppId = issuer.getMdocIacaAppId();
        String iacaRefId = StringUtils.defaultIfBlank(issuer.getMdocIacaRefId(), Constants.EC_SECP256R1_SIGN);
        try {
            X509Certificate iacaCert = loadCertificate(iacaAppId, iacaRefId);
            return MdocCertificateFactory.toPem(iacaCert);
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to export IACA certificate for issuer {}", issuer.getIssuerId(), e);
            throw new CertifyException(ErrorConstants.MDOC_IACA_NOT_CONFIGURED,
                    "Failed to load IACA certificate for issuer: " + issuer.getIssuerId());
        }
    }

    private X509Certificate rebuildAndUploadIaca(String iacaAppId, String refId, String issuerId) throws Exception {
        SignatureCertificate iacaMaterial = loadSignatureCertificate(iacaAppId, refId);
        PrivateKey iacaPrivateKey = iacaMaterial.getCertificateEntry().getPrivateKey();
        PublicKey iacaPublicKey = iacaMaterial.getCertificateEntry().getChain()[0].getPublicKey();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);

        X509Certificate iacaCert = MdocCertificateFactory.buildIacaCertificate(
                iacaPrivateKey,
                iacaPublicKey,
                iacaCnPrefix + issuerId,
                organization,
                organizationalUnit,
                country,
                state,
                location,
                now,
                now.plusDays(iacaValidityDays),
                iacaMaterial.getProviderName());
        uploadCertificate(iacaAppId, refId, iacaCert);
        return iacaCert;
    }

    private void rebuildAndUploadDs(
            String iacaAppId,
            String dsAppId,
            String refId,
            String issuerId,
            X509Certificate iacaCert) throws Exception {
        rebuildAndUploadDs(iacaAppId, dsAppId, refId, refId, issuerId, iacaCert);
    }

    private void rebuildAndUploadDs(
            String iacaAppId,
            String dsAppId,
            String iacaRefId,
            String dsRefId,
            String issuerId,
            X509Certificate iacaCert) throws Exception {
        SignatureCertificate iacaMaterial = loadSignatureCertificate(iacaAppId, iacaRefId);
        SignatureCertificate dsMaterial = loadSignatureCertificate(dsAppId, dsRefId);

        PrivateKey iacaPrivateKey = iacaMaterial.getCertificateEntry().getPrivateKey();
        X500Name iacaSubject = MdocCertificateFactory.toX500Name(iacaCert);
        PublicKey dsPublicKey = dsMaterial.getCertificateEntry().getChain()[0].getPublicKey();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);

        X509Certificate dsCert = MdocCertificateFactory.buildDsCertificate(
                iacaPrivateKey,
                dsPublicKey,
                iacaSubject,
                dsCnPrefix + issuerId,
                organization,
                organizationalUnit,
                country,
                state,
                location,
                now,
                now.plusDays(dsValidityDays),
                iacaMaterial.getProviderName());
        uploadCertificate(dsAppId, dsRefId, dsCert);
    }

    private SignatureCertificate loadSignatureCertificate(String appId, String refId) {
        String timestamp = LocalDateTime.now(ZoneOffset.UTC).toString();
        SignatureCertificate certificate = keymanagerService.getSignatureCertificate(appId, Optional.of(refId), timestamp);
        CertificateEntry<X509Certificate, PrivateKey> entry = certificate.getCertificateEntry();
        if (entry == null || entry.getPrivateKey() == null || entry.getChain() == null || entry.getChain().length == 0) {
            throw new CertifyException(ErrorConstants.MDOC_PKI_PROVISIONING_FAILED,
                    "KeyManager returned incomplete signature certificate for " + appId + "/" + refId);
        }
        return certificate;
    }

    private X509Certificate loadCertificate(String appId, String refId) throws Exception {
        KeyPairGenerateResponseDto response = keymanagerService.getCertificate(appId, Optional.of(refId));
        if (response == null || StringUtils.isBlank(response.getCertificate())) {
            throw new IllegalStateException("No certificate for " + appId + "/" + refId);
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(response.getCertificate().getBytes(StandardCharsets.UTF_8)));
    }

    private void uploadCertificate(String appId, String refId, X509Certificate certificate) throws Exception {
        UploadCertificateRequestDto request = new UploadCertificateRequestDto();
        request.setApplicationId(appId);
        request.setReferenceId(refId);
        request.setCertificateData(MdocCertificateFactory.toPem(certificate));
        keymanagerService.uploadCertificate(request);
    }

    private void generateEcSignKey(String appId, String refId, boolean force) {
        KeyPairGenerateRequestDto request = new KeyPairGenerateRequestDto();
        request.setApplicationId(appId);
        request.setReferenceId(refId);
        request.setForce(force);
        keymanagerService.generateECSignKey("certificate", request);
    }

    private void ensureKeyPolicy(String appId, int validityDays, int preExpireDays) {
        if (keyPolicyRepository.findByApplicationId(appId).isPresent()) {
            return;
        }
        KeyPolicy policy = new KeyPolicy();
        policy.setApplicationId(appId);
        policy.setValidityInDays(validityDays);
        policy.setPreExpireDays(preExpireDays);
        policy.setAccessAllowed("NA");
        policy.setActive(true);
        policy.setCreatedBy(CREATED_BY);
        policy.setCreatedtimes(LocalDateTime.now());
        keyPolicyRepository.save(policy);
        log.info("Registered mdoc key policy for app id {} (validity={}d, preExpire={}d)",
                appId, validityDays, preExpireDays);
    }

    private String buildAppId(String prefix, String issuerId) {
        return KeyManagerAppIdUtil.buildAppId(prefix, issuerId);
    }
}
