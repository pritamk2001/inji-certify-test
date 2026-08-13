package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class IssuerSigningConfigDTO {

    @NotBlank(message = ErrorConstants.INVALID_ISSUER_SIGNING_CONFIG)
    @JsonProperty("signatureCryptoSuite")
    private String signatureCryptoSuite;

    @NotBlank(message = ErrorConstants.INVALID_ISSUER_SIGNING_CONFIG)
    @JsonProperty("signatureAlgo")
    private String signatureAlgo;
}