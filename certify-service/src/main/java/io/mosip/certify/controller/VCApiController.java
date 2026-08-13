/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.services.VCApiIssuanceService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/vc-api")
@Tag(name = "W3C VC API", description = "Endpoints for W3C Verifiable Credentials API issuance (ldp_vc and mso_mdoc)")
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiController {

    @Autowired
    private VCApiIssuanceService vcApiIssuanceService;

    @PostMapping(value = "/credentials/issue", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<VCApiIssueResponse> issueCredential(@Valid @RequestBody VCApiIssueRequest request) {
        log.info("VC API credentials/issue for configuration: {}",
                request.getOptions().getCredentialConfigurationId());
        return ResponseEntity.ok(vcApiIssuanceService.issue(request));
    }
}
