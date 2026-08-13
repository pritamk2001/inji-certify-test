/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiIssueOptions;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VCApiIssuanceServiceTest {

    @Mock
    private CredentialConfigurationService credentialConfigurationService;

    @Mock
    private VCApiTemplateIssuanceSupport vcApiTemplateIssuanceSupport;

    @InjectMocks
    private VCApiIssuanceService vcApiIssuanceService;

    @Test
    public void issue_delegatesToTemplateSupport_forLdpVc() throws Exception {
        VCApiIssueRequest request = buildRequest("farmer-credential", Map.of("fullName", "Jane Doe"));

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);

        JsonLDObject signedVc = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredentialSubject()), eq(config)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc, VCFormats.LDP_VC));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        assertEquals(VCFormats.LDP_VC, response.getFormat());
        assertTrue(response.getVerifiableCredential() instanceof Map);
        assertNotNull(((Map<?, ?>) response.getVerifiableCredential()).get("type"));
        verify(credentialConfigurationService).getCredentialConfigurationById("farmer-credential");
        verify(vcApiTemplateIssuanceSupport).issueFromTemplate(any(), eq(config));
    }

    @Test
    public void issue_returnsStringCredential_forMsoMdoc() throws Exception {
        VCApiIssueRequest request = buildRequest("mdl-credential", Map.of("family_name", "Doe"));

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("mdl-credential");
        config.setCredentialFormat(VCFormats.MSO_MDOC);
        when(credentialConfigurationService.getCredentialConfigurationById("mdl-credential")).thenReturn(config);

        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredentialSubject()), eq(config)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult("base64url-mdoc", VCFormats.MSO_MDOC));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        assertEquals(VCFormats.MSO_MDOC, response.getFormat());
        assertEquals("base64url-mdoc", response.getVerifiableCredential());
    }

    @Test
    public void issue_returnsCredentialMapFromSignedVc() throws Exception {
        VCApiIssueRequest request = buildRequest("farmer-credential",
                Map.of("fullName", "Jane Doe", "idNumber", "12345"));

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);

        JsonLDObject signedVc = JsonLDObject.fromJson(
                "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"credentialSubject\":{\"fullName\":\"Jane Doe\"}}");
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredentialSubject()), eq(config)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc, VCFormats.LDP_VC));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        Map<?, ?> vc = (Map<?, ?>) response.getVerifiableCredential();
        assertEquals("Jane Doe", ((Map<?, ?>) vc.get("credentialSubject")).get("fullName"));
    }

    @Test
    public void issue_whenTemplateSupportThrows_propagatesCertifyException() throws Exception {
        VCApiIssueRequest request = buildRequest("unknown-config", Map.of("fullName", "Jane Doe"));

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("unknown-config");
        when(credentialConfigurationService.getCredentialConfigurationById("unknown-config")).thenReturn(config);
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(any(), eq(config)))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        CertifyException ex = assertThrows(CertifyException.class, () -> vcApiIssuanceService.issue(request));
        assertEquals(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, ex.getErrorCode());
    }

    private VCApiIssueRequest buildRequest(String configId, Map<String, Object> subject) {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(subject);
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId(configId);
        request.setOptions(options);
        return request;
    }
}
