/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Map;

@Data
public class VCApiIssueRequest {

    /**
     * REQUIRED. Claim values matching vcTemplate Velocity placeholders.
     */
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    @NotEmpty(message = ErrorConstants.INVALID_REQUEST)
    private Map<String, Object> credentialSubject;

    /**
     * REQUIRED. Issuance options including credential configuration id.
     */
    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private VCApiIssueOptions options;
}
