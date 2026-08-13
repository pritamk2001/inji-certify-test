package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import lombok.Data;

import java.util.List;

@Data
public class IssuerUpdateRequest {

    @Valid
    private List<MetaDataDisplayDTO> display;

    private String status;

    @JsonProperty("authorizationServers")
    private List<String> authorizationServers;
}
