package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.VCApiIssueOptions;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.services.VCApiIssuanceService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(VCApiController.class)
@TestPropertySource(properties = "mosip.certify.vc-api.enabled=true")
public class VCApiControllerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VCApiIssuanceService vcApiIssuanceService;

    @MockBean
    private ParsedAccessToken parsedAccessToken;

    @MockBean
    private MessageSource messageSource;

    @Test
    public void issueCredential_returnsVerifiableCredential() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("id", "did:example:holder", "fullName", "Jane Doe"));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("my-credential");
        request.setOptions(options);

        VCApiIssueResponse response = new VCApiIssueResponse();
        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("type", java.util.List.of("VerifiableCredential"));
        response.setVerifiableCredential(vc);
        response.setFormat("ldp_vc");
        Mockito.when(vcApiIssuanceService.issue(Mockito.any())).thenReturn(response);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").value("ldp_vc"))
                .andExpect(jsonPath("$.verifiableCredential.type").isArray());
    }

    @Test
    public void issueCredential_returnsMdocStringCredential() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("family_name", "Doe", "id", "did:jwk:eyJ..."));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("mdl-credential");
        request.setOptions(options);

        VCApiIssueResponse response = new VCApiIssueResponse();
        response.setFormat("mso_mdoc");
        response.setVerifiableCredential("base64url-encoded-mdoc");
        Mockito.when(vcApiIssuanceService.issue(Mockito.any())).thenReturn(response);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").value("mso_mdoc"))
                .andExpect(jsonPath("$.verifiableCredential").value("base64url-encoded-mdoc"));
    }

    @Test
    public void issueCredential_withMissingCredentialSubject_thenFail() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("my-credential");
        request.setOptions(options);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_withMissingOptions_thenFail() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_withBlankCredentialConfigurationId_thenFail() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("  ");
        request.setOptions(options);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_whenServiceThrowsCertifyException_thenFail() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("unknown-config");
        request.setOptions(options);

        Mockito.when(vcApiIssuanceService.issue(Mockito.any()))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value(ErrorConstants.CONFIG_NOT_FOUND_BY_ID));
    }

    @Test
    public void issueCredential_whenServiceThrowsUnsupportedFormat_thenFail() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("sdjwt-config");
        request.setOptions(options);

        Mockito.when(vcApiIssuanceService.issue(Mockito.any()))
                .thenThrow(new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                        "VC API supports ldp_vc and mso_mdoc credential formats"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));
    }
}
