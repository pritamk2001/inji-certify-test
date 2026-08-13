/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
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
import io.mosip.certify.mdoc.MdocVcApiIssuanceSupport;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.utils.VcApiTemplateClaimValidator;
import io.mosip.certify.vcformatters.VCFormatter;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.mosip.certify.utils.CredentialUtils.toJsonMap;

@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiTemplateIssuanceSupport {

    @Autowired
    private CredentialCacheKeyGenerator credentialCacheKeyGenerator;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private CredentialFactory credentialFactory;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Autowired
    private CredentialLedgerService credentialLedgerService;

    @Autowired
    private LedgerUtils ledgerUtils;

    @Autowired
    private VelocityEnvConfig velocityEnvConfig;

    @Autowired
    private IssuerResolver issuerResolver;

    @Autowired
    private MdocVcApiIssuanceSupport mdocVcApiIssuanceSupport;

    @Value("${mosip.certify.data-provider-plugin.did-url}")
    private String didUrl;

    @Value("${mosip.certify.data-provider-plugin.rendering-template-id:}")
    private String renderTemplateId;

    @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}")
    private String idPrefix;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730D}")
    private String defaultExpiryDuration;

    @Value("#{${mosip.certify.issuer.ledger-enabled:true}}")
    private boolean isLedgerEnabled;

    public String resolveTemplateName(String credentialConfigurationId) {
        String templateName = credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(credentialConfigurationId);
        if (StringUtils.isBlank(templateName) || "default-key".equals(templateName)) {
            throw new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID,
                    "No template mapping found for credential configuration: " + credentialConfigurationId);
        }
        return templateName;
    }

    public VCApiIssueResult issueFromTemplate(Map<String, Object> credentialSubject, CredentialConfigurationDTO config) {
        VcApiTemplateClaimValidator.validateRequiredClaims(config.getVcTemplate(), credentialSubject);

        String format = config.getCredentialFormat();
        if (VCFormats.LDP_VC.equals(format)) {
            return issueLdpVc(credentialSubject, config);
        }
        if (VCFormats.MSO_MDOC.equals(format)) {
            Issuer issuer = issuerResolver.resolve(config.getIssuerId());
            String credential = mdocVcApiIssuanceSupport.issue(credentialSubject, config, issuer);
            return new VCApiIssueResult(credential, VCFormats.MSO_MDOC);
        }
        throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                "VC API supports ldp_vc and mso_mdoc credential formats; got: " + format);
    }

    private VCApiIssueResult issueLdpVc(Map<String, Object> credentialSubject, CredentialConfigurationDTO config) {
        String templateName = resolveTemplateName(config.getCredentialConfigKeyId());
        Issuer issuer = issuerResolver.resolve(config.getIssuerId());
        JSONObject jsonObject = new JSONObject(credentialSubject);
        if (config.getCredentialTypes() != null) {
            jsonObject.put(Constants.TYPE, config.getCredentialTypes());
        }

        List<String> credentialStatusPurposeList = vcFormatter.getCredentialStatusPurpose(templateName);
        if (credentialStatusPurposeList != null && !credentialStatusPurposeList.isEmpty()
                && config.getContextURLs() != null && config.getContextURLs().contains(VCDM2Constants.URL)) {
            if (!isLedgerEnabled) {
                log.warn("Ledger feature is disabled while revocation is enabled for template {}", templateName);
            }
            statusListCredentialService.addCredentialStatus(jsonObject, credentialStatusPurposeList.getFirst(), issuer);
        }

        Map<String, Object> templateParams = buildTemplateParams(credentialSubject, templateName, jsonObject, issuer);
        Credential cred = credentialFactory.getCredential(VCFormats.LDP_VC)
                .orElseThrow(() -> new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));

        try {
            Map<String, Object> updatedTemplateParams = toJsonMap(templateParams);
            Map<String, Object> rootContext = new HashMap<>(templateParams);
            updatedTemplateParams.put("rootContext", rootContext);
            updatedTemplateParams.put("envConfigs", velocityEnvConfig.getEnvConfigs());

            String unsignedCredential = stripBlankCredentialSubjectId(
                    cred.createCredential(updatedTemplateParams, templateName));
            validateUnsignedCredential(unsignedCredential);

            ZonedDateTime issuanceTime = ZonedDateTime.now(ZoneOffset.UTC);
            String time = issuanceTime.format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            if (isLedgerEnabled) {
                storeLedger(jsonObject, templateParams, time, issuer);
            }

            VCResult<?> result = cred.addProof(unsignedCredential, "",
                    vcFormatter.getProofAlgorithm(templateName),
                    vcFormatter.getAppID(templateName),
                    vcFormatter.getRefID(templateName),
                    vcFormatter.getDidUrl(templateName),
                    vcFormatter.getSignatureCryptoSuite(templateName));

            return new VCApiIssueResult(result.getCredential(), VCFormats.LDP_VC);
        } catch (JSONException e) {
            log.error("VC API credential generation failed: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Invalid JSON data encountered during credential generation");
        }
    }

    private Map<String, Object> buildTemplateParams(Map<String, Object> credentialSubject, String templateName,
                                                    JSONObject jsonObject, Issuer issuer) {
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put(Constants.TEMPLATE_NAME, templateName);
        templateParams.put(Constants.DID_URL, issuer.getDidUrl());
        if (StringUtils.isNotBlank(renderTemplateId)) {
            templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
        }
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

    private String stripBlankCredentialSubjectId(String unsignedCredential) {
        JSONObject unsigned = new JSONObject(unsignedCredential);
        removeBlankCredentialSubjectId(unsigned);
        return unsigned.toString();
    }

    private void removeBlankCredentialSubjectId(JSONObject unsigned) {
        if (!unsigned.has("credentialSubject")) {
            return;
        }
        Object credentialSubject = unsigned.get("credentialSubject");
        if (!(credentialSubject instanceof JSONObject subject)) {
            return;
        }
        if (!subject.has(VCDMConstants.ID)) {
            return;
        }
        Object id = subject.get(VCDMConstants.ID);
        if (id == JSONObject.NULL || (id instanceof String holderId && holderId.isBlank())) {
            subject.remove(VCDMConstants.ID);
        }
    }

    private void validateUnsignedCredential(String unsignedCredential) {
        JSONObject unsigned = new JSONObject(unsignedCredential);
        if (unsigned.has(VCDMConstants.PROOF)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Credential must not include an existing proof");
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
        log.info("VC API ledger entry stored for credentialType: {}", credentialType);
    }

    /**
     * @param credential signed credential — {@link JsonLDObject} for ldp_vc, {@link String} for mso_mdoc
     * @param format     {@link VCFormats#LDP_VC} or {@link VCFormats#MSO_MDOC}
     */
    public record VCApiIssueResult(Object credential, String format) {
    }
}
