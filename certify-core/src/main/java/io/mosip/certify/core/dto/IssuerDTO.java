package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssuerDTO {

    @JsonProperty("issuerId")
    private String issuerId;

    private String status;

    @JsonProperty("credentialIssuerUrl")
    private String credentialIssuerUrl;

    private String identifier;

    @JsonProperty("didUrl")
    private String didUrl;

    private List<MetaDataDisplayDTO> display;

    @JsonProperty("authorizationServers")
    private List<String> authorizationServers;

    @JsonProperty("keyManagerAppId")
    private String keyManagerAppId;

    @JsonProperty("keyManagerRefId")
    private String keyManagerRefId;

    @JsonProperty("signatureCryptoSuite")
    private String signatureCryptoSuite;

    @JsonProperty("signatureAlgo")
    private String signatureAlgo;

    @JsonProperty("mdocIacaAppId")
    private String mdocIacaAppId;

    @JsonProperty("mdocIacaRefId")
    private String mdocIacaRefId;

    @JsonProperty("mdocDsAppId")
    private String mdocDsAppId;

    @JsonProperty("mdocDsRefId")
    private String mdocDsRefId;
}
