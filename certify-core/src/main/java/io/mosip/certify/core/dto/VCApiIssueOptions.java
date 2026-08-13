/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class VCApiIssueOptions {

    /**
     * REQUIRED. Active credential configuration key id (credentialConfigKeyId).
     */
    @NotBlank(message = ErrorConstants.INVALID_REQUEST)
    @JsonProperty("credentialConfigurationId")
    private String credentialConfigurationId;
}
