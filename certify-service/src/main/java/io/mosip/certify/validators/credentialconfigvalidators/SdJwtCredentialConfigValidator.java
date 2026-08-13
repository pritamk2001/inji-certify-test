package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.apache.commons.lang3.StringUtils;

import java.util.Optional;

public class SdJwtCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getSdJwtVct() != null && !credentialConfig.getSdJwtVct().isEmpty()
                && credentialConfig.getSignatureAlgo() != null && !credentialConfig.getSignatureAlgo().isEmpty()
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getDocType() == null && credentialConfig.getCredentialSubjectDefinition() == null &&
                credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSignatureCryptoSuite() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        String issuerId = StringUtils.defaultIfBlank(credentialConfig.getIssuerId(), IssuerConstants.DEFAULT_ISSUER_ID);
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByIssuerIdAndCredentialFormatAndSdJwtVct(
                        issuerId,
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getSdJwtVct());

        return optional.isPresent();
    }
}
