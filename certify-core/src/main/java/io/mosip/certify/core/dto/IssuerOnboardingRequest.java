package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class IssuerOnboardingRequest {

    @NotBlank(message = ErrorConstants.INVALID_ISSUER_ID)
    @JsonProperty("issuerId")
    private String issuerId;

    @Valid
    @NotEmpty(message = ErrorConstants.INVALID_METADATA_DISPLAY)
    private List<MetaDataDisplayDTO> display;

    @Valid
    @JsonProperty("signingConfig")
    private IssuerSigningConfigDTO signingConfig;

    @JsonProperty("authorizationServers")
    private List<String> authorizationServers;

    @JsonProperty("didUrl")
    private String didUrl;
}
