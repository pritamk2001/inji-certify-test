/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.utils.MDocProcessor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static io.mosip.certify.utils.CredentialUtils.toJsonMap;

/**
 * Native (plugin-free) mso_mdoc issuance for the VC API path.
 * <p>
 * Production path: sign with the issuer's KeyManager Document Signer ({@code mdoc_ds_*}).
 * Property-based DS is allowed only when {@code mosip.certify.mdoc.allow-property-ds=true}
 * (local/docker); production must keep that flag {@code false} and fail closed.
 */
@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class MdocVcApiIssuanceSupport {

    private static final String MDOC_DS_SIGN_ALGORITHM = "ES256";

    @Autowired
    private CredentialCacheKeyGenerator credentialCacheKeyGenerator;

    @Autowired
    private CredentialFactory credentialFactory;

    @Autowired
    private MDocProcessor mDocProcessor;

    @Autowired
    private MdocPkiService mdocPkiService;

    @Autowired
    private MdocIssuerKeyCertLoader mdocIssuerKeyCertLoader;

    @Autowired
    private MdocLocalDsCoseSigner mdocLocalDsCoseSigner;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialLedgerService credentialLedgerService;

    @Autowired
    private LedgerUtils ledgerUtils;

    @Autowired
    private VelocityEnvConfig velocityEnvConfig;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730D}")
    private String defaultExpiryDuration;

    @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}")
    private String idPrefix;

    @Value("#{${mosip.certify.issuer.ledger-enabled:true}}")
    private boolean isLedgerEnabled;

    /**
     * When false (default), mdoc signing requires issuer KeyManager DS refs.
     * Enable only for local/docker so property {@code mosip.certify.mdoc.issuer-key-cert} may be used.
     */
    @Value("${mosip.certify.mdoc.allow-property-ds:false}")
    private boolean allowPropertyDs;

    public String issue(Map<String, Object> credentialSubject, CredentialConfigurationDTO config, Issuer issuer) {
        if (StringUtils.isBlank(config.getDocType())) {
            throw new CertifyException(ErrorConstants.MDOC_DOCTYPE_REQUIRED,
                    "docType is required on credential configuration for mso_mdoc issuance");
        }

        String templateName = resolveTemplateName(config.getCredentialConfigKeyId());
        JSONObject jsonObject = new JSONObject(credentialSubject);
        jsonObject.put(Constants.TYPE, config.getDocType());

        Map<String, Object> templateParams = buildTemplateParams(credentialSubject, templateName, jsonObject, issuer, config);
        Credential cred = credentialFactory.getCredential(VCFormats.MSO_MDOC)
                .orElseThrow(() -> new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));

        try {
            Map<String, Object> updatedTemplateParams = toJsonMap(templateParams);
            Map<String, Object> rootContext = new HashMap<>(templateParams);
            updatedTemplateParams.put("rootContext", rootContext);
            updatedTemplateParams.put("envConfigs", velocityEnvConfig.getEnvConfigs());

            String unsignedCredential = cred.createCredential(updatedTemplateParams, templateName);

            ZonedDateTime issuanceTime = ZonedDateTime.now(ZoneOffset.UTC);
            String time = issuanceTime.format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            if (isLedgerEnabled) {
                storeLedger(jsonObject, templateParams, time, issuer);
            }

            return signMdoc(unsignedCredential, issuer);
        } catch (JSONException e) {
            log.error("VC API mdoc credential generation failed: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Invalid JSON data encountered during mdoc credential generation");
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("VC API mdoc issuance failed: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED,
                    "Failed to issue mso_mdoc credential via VC API");
        }
    }

    private String signMdoc(String unsignedCredential, Issuer issuer) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> mDocJson = objectMapper.readValue(unsignedCredential, Map.class);
        Map<String, Object> saltedNamespaces = MDocProcessor.addRandomSalts(mDocJson);
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> taggedNamespaces = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, namespaceDigests);
        byte[] signedMSO = signMso(mso, issuer);
        Map<String, Object> issuerSigned = MDocProcessor.createIssuerSignedStructure(taggedNamespaces, signedMSO);

        Map<String, Object> mDocSignedCredential = new HashMap<>();
        mDocSignedCredential.put(Constants.DOCTYPE, mso.get(Constants.DOCTYPE));
        mDocSignedCredential.put("issuerSigned", issuerSigned);

        byte[] cborIssuerSigned = MDocProcessor.encodeToCBOR(mDocSignedCredential);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(cborIssuerSigned);
    }

    private byte[] signMso(Map<String, Object> mso, Issuer issuer) throws Exception {
        if (hasIssuerDocumentSigner(issuer)) {
            // ROOT-style lazy rotation: rotate DS when near expiry / expired, then sign
            mdocPkiService.ensureDocumentSignerCurrent(issuer);
            String dsAppId = issuer.getMdocDsAppId();
            String dsRefId = StringUtils.defaultIfBlank(issuer.getMdocDsRefId(), Constants.EC_SECP256R1_SIGN);
            log.info("Signing VC API mdoc with issuer KeyManager DS appId={}, refId={}", dsAppId, dsRefId);
            return mDocProcessor.signMSO(mso, dsAppId, dsRefId, MDOC_DS_SIGN_ALGORITHM);
        }
        if (!allowPropertyDs) {
            throw new CertifyException(ErrorConstants.MDOC_ISSUER_DS_NOT_CONFIGURED,
                    "Issuer is missing mdoc Document Signer KeyManager refs (mdocDsAppId). "
                            + "Provision mdoc PKI at issuer onboarding. Property DS is disabled "
                            + "(mosip.certify.mdoc.allow-property-ds=false); enable only for non-prod.");
        }
        log.warn("Issuer {} has no mdoc DS KeyManager refs; using non-prod property Document Signer "
                        + "(mosip.certify.mdoc.allow-property-ds=true)",
                issuer != null ? issuer.getIssuerId() : "null");
        MdocDsKeyMaterial keyMaterial = mdocIssuerKeyCertLoader.load();
        return mDocProcessor.signMSOWithLocalDs(mso, keyMaterial, mdocLocalDsCoseSigner);
    }

    private static boolean hasIssuerDocumentSigner(Issuer issuer) {
        return issuer != null && StringUtils.isNotBlank(issuer.getMdocDsAppId());
    }

    private String resolveTemplateName(String credentialConfigurationId) {
        String templateName = credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(credentialConfigurationId);
        if (StringUtils.isBlank(templateName) || "default-key".equals(templateName)) {
            throw new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID,
                    "No template mapping found for credential configuration: " + credentialConfigurationId);
        }
        return templateName;
    }

    private Map<String, Object> buildTemplateParams(Map<String, Object> credentialSubject, String templateName,
                                                    JSONObject jsonObject, Issuer issuer,
                                                    CredentialConfigurationDTO config) {
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put(Constants.TEMPLATE_NAME, templateName);
        templateParams.put(Constants.DID_URL, issuer.getDidUrl());
        templateParams.put("_doctype", config.getDocType());
        Object holderId = credentialSubject.get(VCDMConstants.ID);
        if (holderId != null && StringUtils.isNotBlank(holderId.toString())) {
            templateParams.put(Constants._HOLDER_ID, holderId.toString());
        }
        templateParams.putAll(jsonObject.toMap());
        if (StringUtils.isNotBlank(idPrefix)) {
            templateParams.put(VCDMConstants.CREDENTIAL_ID, idPrefix + UUID.randomUUID());
        }
        ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneOffset.UTC);
        String time = zonedDateTime.format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        Duration duration = parseExpiryDuration();
        String expiryTime = zonedDateTime.plus(duration).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        templateParams.put(VCDM2Constants.VALID_FROM, time);
        templateParams.put(VCDM2Constants.VALID_UNTIL, expiryTime);
        return templateParams;
    }

    private Duration parseExpiryDuration() {
        try {
            return Duration.parse(defaultExpiryDuration);
        } catch (DateTimeParseException e) {
            log.warn("Incorrect expiry duration format: {}. Using P730D", defaultExpiryDuration);
            return Duration.parse("P730D");
        }
    }

    private void storeLedger(JSONObject jsonObject, Map<String, Object> templateParams, String time, Issuer issuer) {
        Map<String, Object> indexedAttributes = ledgerUtils.extractIndexedAttributes(jsonObject);
        String credentialType = LedgerUtils.extractCredentialType(jsonObject);
        String credentialId = null;
        if (templateParams.containsKey(VCDMConstants.CREDENTIAL_ID)) {
            credentialId = templateParams.get(VCDMConstants.CREDENTIAL_ID).toString();
        }
        CredentialStatusDetail credentialStatusDetail = ledgerUtils.extractCredentialStatusDetails(jsonObject);
        LocalDateTime issuanceDate = LocalDateTime.parse(time, DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        credentialLedgerService.storeLedgerEntry(credentialId, issuer.getDidUrl(), credentialType, credentialStatusDetail,
                indexedAttributes, issuanceDate);
        log.info("VC API mdoc ledger entry stored for credentialType: {}", credentialType);
    }
}
