/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.vcformatters;

import java.io.StringWriter;
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.tools.generic.DateTool;
import org.apache.velocity.tools.generic.EscapeTool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.cache.annotation.Cacheable;


import org.json.JSONArray;
import org.json.JSONObject;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.core.spi.RenderingTemplateService;
import io.mosip.certify.services.CredentialUtils;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import static io.mosip.certify.core.constants.Constants.*;


@Slf4j
@Service
public class VelocityTemplatingEngineImpl implements VCFormatter {
    VelocityEngine engine;

    @Autowired
    CredentialConfigRepository credentialConfigRepository;
    @Autowired
    RenderingTemplateService renderingTemplateService;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730d}")
    String defaultExpiryDuration;

    @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}")
    String idPrefix;

    @PostConstruct
    public void initialize() {
        engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
        log.info("VelocityTemplatingEngineImpl initialized. Using Spring Cache for CredentialConfig.");
    }

    /**
     * Internal method to fetch CredentialConfig, leveraging Spring Cache.
     * The key is expected to be "credentialType:context:credentialFormat".
     */
    @Cacheable(cacheNames = "credentialConfig", key = "#templateKey")
    protected CredentialConfig getCachedCredentialConfig(String templateKey) {
        log.debug("Cache miss for credentialConfig with key: {}. Fetching from DB.", templateKey);
        if (templateKey == null || !templateKey.contains(DELIMITER)) {
            log.error("Invalid templateKey format for getCachedCredentialConfig: {}", templateKey);
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "Invalid template key format: " + templateKey);
        }

        String[] parts = templateKey.split(DELIMITER, -1);
        if (parts.length < 2) {
            log.error("Invalid templateKey format for getCachedCredentialConfig: {}", templateKey);
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "Invalid template key format: " + templateKey);
        }

        // issuerId::credentialType::context::credentialFormat
        if (parts.length == 4) {
            return credentialConfigRepository
                    .findByIssuerIdAndCredentialFormatAndCredentialTypeAndContext(
                            parts[0], parts[3], parts[1], parts[2])
                    .orElseThrow(() -> configNotFound(templateKey));
        }

        // issuerId::format::doctype|vct
        if (parts.length == 3
                && (Objects.equals(parts[1], VCFormats.MSO_MDOC) || Objects.equals(parts[1], VCFormats.VC_SD_JWT))) {
            if (Objects.equals(parts[1], VCFormats.MSO_MDOC)) {
                return credentialConfigRepository.findByIssuerIdAndCredentialFormatAndDocType(parts[0], parts[1], parts[2])
                        .orElseThrow(() -> configNotFound(templateKey));
            }
            return credentialConfigRepository.findByIssuerIdAndCredentialFormatAndSdJwtVct(parts[0], parts[1], parts[2])
                    .orElseThrow(() -> configNotFound(templateKey));
        }

        // Legacy: format::doctype|vct
        if (parts.length == 2) {
            String credentialFormat = parts[0];
            if (Objects.equals(credentialFormat, VCFormats.MSO_MDOC)) {
                return credentialConfigRepository.findByCredentialFormatAndDocType(credentialFormat, parts[1])
                        .orElseThrow(() -> configNotFound(templateKey));
            }
            if (Objects.equals(credentialFormat, VCFormats.VC_SD_JWT)) {
                return credentialConfigRepository.findByCredentialFormatAndSdJwtVct(credentialFormat, parts[1])
                        .orElseThrow(() -> configNotFound(templateKey));
            }
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "Undefined VC Format");
        }

        // Legacy: credentialType::context::credentialFormat
        if (parts.length == 3) {
            return credentialConfigRepository
                    .findByCredentialFormatAndCredentialTypeAndContext(parts[2], parts[0], parts[1])
                    .orElseThrow(() -> configNotFound(templateKey));
        }

        throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "Invalid template key format: " + templateKey);
    }

    private CertifyException configNotFound(String templateKey) {
        log.error("CredentialConfig not found in DB for key: {}", templateKey);
        return new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND,
                "CredentialConfig not found for key: " + templateKey);
    }


    /**
     * Gets the proof/signature algorithm for this template
     * @param templateName is the name of the template.
     * @return Signature Algorithm name. This can also be null
     */
    @Override
    public String getProofAlgorithm(String templateName){
        // return templateCache.get(templateName).get("signatureAlgo"); // OLD
        return getCachedCredentialConfig(templateName).getSignatureAlgo(); // NEW
    }

    /**
     * Get the URL of the public key for this template
     * @param templateName is the name of the template.
     * @return URL of the public key.
     */
    @Override
    public String getDidUrl(String templateName){
        // return templateCache.get(templateName).get("didUrl"); // OLD
        return getCachedCredentialConfig(templateName).getDidUrl(); // NEW
    }

    /**
     * Get the refid of the key stored in keymanager.
     * @param templateName is the name of the template.
     * @return refid for the keymanager.
     */
    @Override
    public String getRefID(String templateName){
        // return templateCache.get(templateName).get("keyManagerRefId"); // OLD
        return getCachedCredentialConfig(templateName).getKeyManagerRefId(); // NEW
    }

    /**
     * Get the appid of the key stored in keymanager
     * @param templateName is the name of the template.
     * @return appid of the keymanager.
     */
    @Override
    public String getAppID(String templateName){

        return getCachedCredentialConfig(templateName).getKeyManagerAppId(); // NEW
    }

    /**
     * Gets the selective disclosure information.
     * @param templateName is the name of the template
     * @return the list of selective disclosure paths. In case of null
     * it returns an empty list.
     */
    @Override
    public List<String> getSelectiveDisclosureInfo(String templateName){
        String sdClaimValue = getCachedCredentialConfig(templateName).getSdClaim(); // NEW
        return Optional.ofNullable(sdClaimValue)
                .map(sd -> Arrays.asList(sd.split(",")))
                .orElseGet(ArrayList::new);
    }

    /**
     * Gets the crypto suite used for VC signature or proof generation
     * @param templateName is the name of the template
     * @return the crypto suite used for VC signature or proof generation
     */
    @Override
    public String getSignatureCryptoSuite(String templateName) {
        return getCachedCredentialConfig(templateName).getSignatureCryptoSuite(); // NEW
    }

    @Override
    public List<String> getCredentialStatusPurpose(String templateName) {
        return getCachedCredentialConfig(templateName).getCredentialStatusPurposes();
    }

    @Override
    public List<Map<String, Object>> getQRSettings(String templateName) {
        return getCachedCredentialConfig(templateName).getQrSettings();
    }

    @Override
    public String getQRSignatureAlgo(String templateName) {
        return getCachedCredentialConfig(templateName).getQrSignatureAlgo();
    }

    /**
     * performs the templating
     * NOTE: the defaultSettings map should have the "templateName" key set to
     * "${sort(CREDENTIALTYPE1,CREDENTIALTYPE2,CREDENTIALTYPE3...)}:${sort(VC_CONTEXT1,VC_CONTENXT2,VC_CONTEXT3...)}"
     *
     * @param updatedTemplateParams is the merged input from the DataProvider plugin and all the default settings as one single map
     * @return templated VC as a String
     */
    @SneakyThrows
    @Override
    public String format(Map<String, Object> updatedTemplateParams) {
        // TODO: Isn't template name becoming too complex with VC_CONTEXTS & CREDENTIAL_TYPES both?
        String templateName = updatedTemplateParams.get(TEMPLATE_NAME).toString();
        String issuer = updatedTemplateParams.get(DID_URL).toString();
        String vcTemplateString = getCachedCredentialConfig(templateName).getVcTemplate(); // NEW
        vcTemplateString = new String(Base64.decodeBase64(vcTemplateString));
        StringWriter writer = new StringWriter();
        // TODO: Eventually, the credentialSubject from the plugin will be templated as-is
        // Date: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/DateTool.html
        updatedTemplateParams.put("_dateTool", new DateTool());
        // Escape: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/EscapeTool.html
        updatedTemplateParams.put("_esc", new EscapeTool());
        // add the issuer value
        updatedTemplateParams.put("_issuer", issuer);
        if (updatedTemplateParams.containsKey(Constants.RENDERING_TEMPLATE_ID) && templateName.contains(VCDM2Constants.URL)) {
            try {
                updatedTemplateParams.put("_renderMethodSVGdigest",
                        CredentialUtils.getDigestMultibase(renderingTemplateService.getTemplate(
                                (String) updatedTemplateParams.get(Constants.RENDERING_TEMPLATE_ID)).getTemplate()));
            } catch (RenderingTemplateException e) {
                log.error("Template: " + updatedTemplateParams.get(Constants.RENDERING_TEMPLATE_ID) + " not available in DB", e);
            }
        }
        VelocityContext context = new VelocityContext(updatedTemplateParams);
        engine.evaluate(context, writer, /*logTag */ templateName, vcTemplateString); // use vcTemplateString
        JSONObject jsonObject = new JSONObject(writer.toString());
        if (updatedTemplateParams.containsKey(VCDMConstants.CREDENTIAL_ID)) {
            jsonObject.put(VCDMConstants.ID, updatedTemplateParams.get(VCDMConstants.CREDENTIAL_ID));
        }
        if(updatedTemplateParams.containsKey(VCDM2Constants.CREDENTIAL_STATUS) && templateName.contains(VCDM2Constants.URL)) {
            jsonObject.put(VCDM2Constants.CREDENTIAL_STATUS, updatedTemplateParams.get(VCDM2Constants.CREDENTIAL_STATUS));
        }
        if( updatedTemplateParams.containsKey(VCTYPE) && updatedTemplateParams.containsKey(CONFIRMATION)
                && updatedTemplateParams.containsKey(ISSUER)) {
            jsonObject.put(VCTYPE, updatedTemplateParams.get(VCTYPE));
            jsonObject.put(CONFIRMATION, updatedTemplateParams.get(CONFIRMATION));
            jsonObject.put(ISSUER, updatedTemplateParams.get(ISSUER));
        }

        return jsonObject.toString();
    }

    /**
     * performs the QR data templating
     *
     * @param updatedTemplateParams is the merged input from the DataProvider plugin and all the default settings as one single map
     * @return templated QR data as a JSONArray
     */
    @Override
    public JSONArray formatQRData(Map<String, Object> updatedTemplateParams) {
        String templateName = updatedTemplateParams.get(TEMPLATE_NAME).toString();
        List<Map<String, Object>> qrSettings = getQRSettings(templateName);
        if(qrSettings == null || qrSettings.isEmpty()) {
            return null;
        }
        String qrTemplateString = "";
        try {
            qrTemplateString = objectMapper.writeValueAsString(qrSettings);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR, "Error processing JSON data for QR code generation.");
        }
        StringWriter writer = new StringWriter();
        updatedTemplateParams.put("_esc", new EscapeTool());
        VelocityContext context = new VelocityContext(updatedTemplateParams);
        engine.evaluate(context, writer, /*logTag */ templateName, qrTemplateString); // use qrTemplateString
        return new JSONArray(writer.toString());
    }
}