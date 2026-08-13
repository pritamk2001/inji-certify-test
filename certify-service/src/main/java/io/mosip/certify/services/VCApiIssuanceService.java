/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiIssuanceService {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCApiTemplateIssuanceSupport vcApiTemplateIssuanceSupport;

    public VCApiIssueResponse issue(VCApiIssueRequest request) {
        String credentialConfigurationId = request.getOptions().getCredentialConfigurationId();
        log.info("VC API issue request for configuration: {}", credentialConfigurationId);

        try {
            CredentialConfigurationDTO config = credentialConfigurationService
                    .getCredentialConfigurationById(credentialConfigurationId);

            VCApiTemplateIssuanceSupport.VCApiIssueResult result = vcApiTemplateIssuanceSupport
                    .issueFromTemplate(request.getCredentialSubject(), config);

            VCApiIssueResponse response = new VCApiIssueResponse();
            response.setFormat(result.format());
            response.setVerifiableCredential(toResponseCredential(result));
            return response;
        } catch (JsonProcessingException e) {
            log.error("VC API issue request failed during configuration lookup: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Invalid JSON data encountered during credential issuance");
        }
    }

    private Object toResponseCredential(VCApiTemplateIssuanceSupport.VCApiIssueResult result) {
        if (VCFormats.MSO_MDOC.equals(result.format())) {
            if (result.credential() instanceof String credential) {
                return credential;
            }
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Unable to convert mso_mdoc credential to response format");
        }
        return toCredentialMap(result.credential());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toCredentialMap(Object credential) {
        if (credential instanceof JsonLDObject jsonLDObject) {
            Object json = jsonLDObject.getJsonObject();
            if (json instanceof Map<?, ?> map) {
                return new LinkedHashMap<>((Map<String, Object>) map);
            }
        }
        if (credential instanceof Map<?, ?> map) {
            return new LinkedHashMap<>((Map<String, Object>) map);
        }
        throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                "Unable to convert verifiable credential to response format");
    }
}
