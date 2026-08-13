/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.MDocCredential;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.utils.MDocProcessor;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MdocVcApiIssuanceSupportTest {

    private static final String TEMPLATE_NAME = "default|mso_mdoc|org.iso.18013.5.1.mDL";

    @InjectMocks
    private MdocVcApiIssuanceSupport support;

    @Mock
    private CredentialCacheKeyGenerator credentialCacheKeyGenerator;
    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private MDocProcessor mDocProcessor;
    @Mock
    private MdocPkiService mdocPkiService;
    @Mock
    private MdocIssuerKeyCertLoader mdocIssuerKeyCertLoader;
    @Mock
    private MdocLocalDsCoseSigner mdocLocalDsCoseSigner;
    @Mock
    private CredentialLedgerService credentialLedgerService;
    @Mock
    private LedgerUtils ledgerUtils;
    @Mock
    private VelocityEnvConfig velocityEnvConfig;
    @Mock
    private MDocCredential mDocCredential;

    private Issuer issuer;
    private final ObjectMapper realObjectMapper = new ObjectMapper();

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(support, "defaultExpiryDuration", "P730D");
        ReflectionTestUtils.setField(support, "idPrefix", "");
        ReflectionTestUtils.setField(support, "isLedgerEnabled", false);
        ReflectionTestUtils.setField(support, "allowPropertyDs", false);
        ReflectionTestUtils.setField(support, "objectMapper", realObjectMapper);
        when(velocityEnvConfig.getEnvConfigs()).thenReturn(new HashMap<>());
        issuer = new Issuer();
        issuer.setIssuerId("mdl-issuer");
        issuer.setDidUrl("did:web:mdl.issuer");
    }

    @Test
    public void issue_throws_whenDocTypeMissing() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("mdl");
        config.setCredentialFormat(VCFormats.MSO_MDOC);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issue(Map.of("family_name", "Doe"), config, issuer));
        assertEquals(ErrorConstants.MDOC_DOCTYPE_REQUIRED, ex.getErrorCode());
    }

    @Test
    public void issue_throws_whenTemplateMissing() {
        CredentialConfigurationDTO config = mdocConfig();
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId("mdl"))
                .thenReturn("default-key");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issue(Map.of("family_name", "Doe"), config, issuer));
        assertEquals(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, ex.getErrorCode());
    }

    @Test
    public void issue_withoutIssuerDs_failsClosed_whenPropertyDsDisabled() {
        CredentialConfigurationDTO config = mdocConfig();
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId("mdl"))
                .thenReturn(TEMPLATE_NAME);
        when(credentialFactory.getCredential(VCFormats.MSO_MDOC)).thenReturn(Optional.of(mDocCredential));

        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 1);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("nameSpaces", Map.of("org.iso.18013.5.1", List.of(element)));
        try {
            when(mDocCredential.createCredential(anyMap(), eq(TEMPLATE_NAME)))
                    .thenReturn(realObjectMapper.writeValueAsString(mDocJson));
            Map<String, Object> mso = new HashMap<>();
            mso.put("docType", "org.iso.18013.5.1.mDL");
            when(mDocProcessor.createMobileSecurityObject(any(), any())).thenReturn(mso);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issue(Map.of("family_name", "Doe"), config, issuer));
        assertEquals(ErrorConstants.MDOC_ISSUER_DS_NOT_CONFIGURED, ex.getErrorCode());
        verify(mdocIssuerKeyCertLoader, org.mockito.Mockito.never()).load();
    }

    @Test
    public void issue_success_withPropertyDs_whenAllowed() throws Exception {
        ReflectionTestUtils.setField(support, "allowPropertyDs", true);
        CredentialConfigurationDTO config = mdocConfig();
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId("mdl"))
                .thenReturn(TEMPLATE_NAME);
        when(credentialFactory.getCredential(VCFormats.MSO_MDOC)).thenReturn(Optional.of(mDocCredential));

        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 1);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("nameSpaces", Map.of("org.iso.18013.5.1", List.of(element)));
        String unsignedJson = realObjectMapper.writeValueAsString(mDocJson);
        when(mDocCredential.createCredential(anyMap(), eq(TEMPLATE_NAME))).thenReturn(unsignedJson);

        MdocDsKeyMaterial keyMaterial = org.mockito.Mockito.mock(MdocDsKeyMaterial.class);
        when(mdocIssuerKeyCertLoader.load()).thenReturn(keyMaterial);

        Map<String, Object> mso = new HashMap<>();
        mso.put("docType", "org.iso.18013.5.1.mDL");
        when(mDocProcessor.createMobileSecurityObject(any(), any())).thenReturn(mso);
        when(mDocProcessor.signMSOWithLocalDs(eq(mso), eq(keyMaterial), eq(mdocLocalDsCoseSigner)))
                .thenReturn(createMockCoseSign1());

        String holderJwk = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x\",\"y\":\"y\"}".getBytes());
        String result = support.issue(Map.of(
                "family_name", "Doe",
                "id", "did:jwk:" + holderJwk), config, issuer);

        assertNotNull(result);
        assertFalse(result.isBlank());
        assertEquals(true, result.matches("^[A-Za-z0-9_-]+$"));
        verify(mdocIssuerKeyCertLoader).load();
        verify(mDocProcessor).signMSOWithLocalDs(any(), eq(keyMaterial), eq(mdocLocalDsCoseSigner));
    }

    @Test
    public void issue_withIssuerMdocDs_signsViaKeyManager() throws Exception {
        issuer.setMdocDsAppId("CERTIFY_DS_MDL_ISSUER");
        issuer.setMdocDsRefId("EC_SECP256R1_SIGN");
        issuer.setMdocIacaAppId("CERTIFY_IACA_MDL_ISSUER");
        issuer.setMdocIacaRefId("EC_SECP256R1_SIGN");

        CredentialConfigurationDTO config = mdocConfig();
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId("mdl"))
                .thenReturn(TEMPLATE_NAME);
        when(credentialFactory.getCredential(VCFormats.MSO_MDOC)).thenReturn(Optional.of(mDocCredential));

        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 1);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("nameSpaces", Map.of("org.iso.18013.5.1", List.of(element)));
        when(mDocCredential.createCredential(anyMap(), eq(TEMPLATE_NAME)))
                .thenReturn(realObjectMapper.writeValueAsString(mDocJson));

        Map<String, Object> mso = new HashMap<>();
        mso.put("docType", "org.iso.18013.5.1.mDL");
        when(mDocProcessor.createMobileSecurityObject(any(), any())).thenReturn(mso);
        when(mDocProcessor.signMSO(eq(mso), eq("CERTIFY_DS_MDL_ISSUER"), eq("EC_SECP256R1_SIGN"), eq("ES256")))
                .thenReturn(createMockCoseSign1());

        String result = support.issue(Map.of("family_name", "Doe"), config, issuer);

        assertNotNull(result);
        assertFalse(result.isBlank());
        verify(mdocPkiService).ensureDocumentSignerCurrent(issuer);
        verify(mDocProcessor).signMSO(eq(mso), eq("CERTIFY_DS_MDL_ISSUER"), eq("EC_SECP256R1_SIGN"), eq("ES256"));
        verify(mdocIssuerKeyCertLoader, org.mockito.Mockito.never()).load();
    }

    private CredentialConfigurationDTO mdocConfig() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("mdl");
        config.setCredentialFormat(VCFormats.MSO_MDOC);
        config.setDocType("org.iso.18013.5.1.mDL");
        config.setIssuerId("mdl-issuer");
        return config;
    }

    private byte[] createMockCoseSign1() throws Exception {
        co.nstant.in.cbor.model.Array coseArray = new co.nstant.in.cbor.model.Array();
        coseArray.add(new co.nstant.in.cbor.model.ByteString(new byte[]{(byte) 0xa1, 0x01, 0x26}));
        coseArray.add(new co.nstant.in.cbor.model.Map());
        coseArray.add(new co.nstant.in.cbor.model.ByteString(new byte[]{1, 2, 3, 4}));
        coseArray.add(new co.nstant.in.cbor.model.ByteString(new byte[]{5, 6, 7, 8}));
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        new co.nstant.in.cbor.CborEncoder(baos).encode(coseArray);
        return baos.toByteArray();
    }
}
