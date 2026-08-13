/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@Transactional
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CredentialConfigMapper credentialConfigMapper;

    @Autowired
    private IssuerResolver issuerResolver;

    @Autowired
    private IssuerRepository issuerRepository;

    @Value("${mosip.certify.domain.url}")
    private String credentialIssuer;

    @Value("${mosip.certify.allow-c-nonce:false}")
    private boolean allowCNonce;

    @Value("${mosip.certify.authorization.url}")
    private String authUrl;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.plugin-mode}")
    private String pluginMode;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, String>> issuerDisplay;

    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedCredentialStatusPurposes;

    @Value("#{${mosip.certify.credential-config.cryptographic-binding-methods-supported}}")
    private LinkedHashMap<String, List<String>> cryptographicBindingMethodsSupportedMap;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    @Value("#{${mosip.certify.credential-config.proof-types-supported}}")
    private LinkedHashMap<String, Object> proofTypesSupported;

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    @Value("#{${mosip.certify.credential-config.as-mapping:{}}}")
    private Map<String, String> authorizationServerMapping;

    private static final String CREDENTIAL_CONFIG_CACHE_NAME = "credentialConfig";

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) {
        Issuer issuer = issuerResolver.resolve(
                org.apache.commons.lang3.StringUtils.defaultIfBlank(
                        credentialConfigurationDTO.getIssuerId(), IssuerConstants.DEFAULT_ISSUER_ID));
        credentialConfigurationDTO.setIssuerId(issuer.getIssuerId());
        applyIssuerSigningKeys(credentialConfigurationDTO, issuer);
        validateIssuerCredentialBinding(credentialConfigurationDTO, issuer);

        validateCredentialConfiguration(credentialConfigurationDTO, true);

        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        credentialConfig.setIssuerId(issuer.getIssuerId());
        if (credentialConfig.getDidUrl() == null || credentialConfig.getDidUrl().isBlank()) {
            credentialConfig.setDidUrl(issuer.getDidUrl());
        }
        return saveCredentialConfiguration(credentialConfig);
    }

    private CredentialConfigResponse saveCredentialConfiguration(CredentialConfig credentialConfig) {
        credentialConfig.setConfigId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);

        credentialConfig.setCryptographicBindingMethodsSupported(
                cryptographicBindingMethodsSupportedMap.get(credentialConfig.getCredentialFormat()));
        credentialConfig.setCredentialSigningAlgValuesSupported(
                Collections.singletonList(credentialConfig.getSignatureCryptoSuite()));
        credentialConfig.setProofTypesSupported(proofTypesSupported);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Added credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());
        credentialConfigResponse.setIssuerId(savedConfig.getIssuerId());

        return credentialConfigResponse;
    }

    private void validateCredentialConfiguration(CredentialConfigurationDTO credentialConfig, boolean shouldCheckDuplicate) {

        if (credentialConfig.getCredentialStatusPurposes() != null && credentialConfig.getCredentialStatusPurposes().size() > 1) {
            throw new CertifyException(ErrorConstants.MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED,
                    "Multiple credential status purposes are not supported. Please specify only one.");
        }

        if (credentialConfig.getCredentialStatusPurposes() != null
                && !credentialConfig.getCredentialStatusPurposes().isEmpty()
                && !allowedCredentialStatusPurposes.contains(credentialConfig.getCredentialStatusPurposes().getFirst())) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE,
                    "Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }

        if (pluginMode.equals("DataProvider")
                && (credentialConfig.getVcTemplate() == null || credentialConfig.getVcTemplate().isEmpty())) {
            throw new CertifyException(ErrorConstants.CREDENTIAL_TEMPLATE_REQUIRED,
                    "A Credential Template is required for issuers using the Data Provider plugin.");
        }

        if (credentialConfig.getQrSettings() == null || credentialConfig.getQrSettings().isEmpty()) {
            if (credentialConfig.getQrSignatureAlgo() != null) {
                throw new CertifyException(ErrorConstants.QR_SIGNATURE_ALGO_NOT_ALLOWED,
                        "QR signature algorithm is not allowed when QR settings are not set.");
            }
        } else {
            String qrSignatureAlgo = credentialConfig.getQrSignatureAlgo();
            if (qrSignatureAlgo != null && !qrSignatureAlgo.isEmpty() && !keyAliasMapper.containsKey(qrSignatureAlgo)) {
                throw new CertifyException(ErrorConstants.INVALID_QR_SIGNING_ALGORITHM,
                        "The algorithm " + qrSignatureAlgo + " is not supported for QR signing. The supported values are: "
                                + keyAliasMapper.keySet());
            }
        }

        switch (credentialConfig.getCredentialFormat()) {
            case VCFormats.LDP_VC:
                if (!LdpVcCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_MANDATORY_FIELDS_MISSING,
                            "Fields context, credentialType, and signatureCryptoSuite are mandatory for the ldp_vc format.");
                }
                if (shouldCheckDuplicate
                        && LdpVcCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_CONFIG_EXISTS,
                            "Configuration already exists for the specified context and credentialType.");
                }
                validateKeyAliasMapperConfiguration(credentialConfig);
                break;
            case VCFormats.MSO_MDOC:
                if (!MsoMdocCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_MANDATORY_FIELDS_MISSING,
                            "Fields doctype and signatureCryptoSuite are mandatory for the mso_mdoc format.");
                }
                if (shouldCheckDuplicate
                        && MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_CONFIG_EXISTS,
                            "Configuration already exists for the specified doctype.");
                }
                break;
            case VCFormats.VC_SD_JWT:
                if (!SdJwtCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.VC_SD_JWT_MANDATORY_FIELDS_MISSING,
                            "Fields vct and signatureAlgo are mandatory for the vc+sd-jwt format.");
                }
                if (shouldCheckDuplicate
                        && SdJwtCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.VC_SD_JWT_CONFIG_EXISTS,
                            "Configuration already exists for the specified vct.");
                }
                break;
            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_FORMAT,
                        "Unsupported credential format: " + credentialConfig.getCredentialFormat());
        }
    }

    private void validateKeyAliasMapperConfiguration(CredentialConfigurationDTO credentialConfig) {
        if (pluginMode.equals("VCIssuance")) {
            return;
        }
        String signatureCryptoSuite = credentialConfig.getSignatureCryptoSuite();
        String signatureAlgo = credentialConfig.getSignatureAlgo();

        if (signatureCryptoSuite != null) {
            if (!credentialSigningAlgValuesSupportedMap.containsKey(signatureCryptoSuite)) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE,
                        "Unsupported signature crypto suite: " + signatureCryptoSuite);
            }

            List<String> signatureAlgos = credentialSigningAlgValuesSupportedMap.get(signatureCryptoSuite);
            if (signatureAlgo == null) {
                signatureAlgo = signatureAlgos.getFirst();
                credentialConfig.setSignatureAlgo(signatureAlgo);
            } else if (!signatureAlgos.contains(signatureAlgo)) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO,
                        "Signature algorithm " + signatureAlgo + " is not supported for the crypto suite: "
                                + signatureCryptoSuite);
            }
        }

        List<List<String>> keyAliasList = keyAliasMapper.get(credentialConfig.getSignatureAlgo());
        if (keyAliasList == null || keyAliasList.isEmpty()) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND,
                    "No key chooser configuration found for the signature crypto suite: "
                            + credentialConfig.getSignatureCryptoSuite());
        }

        boolean isMatch = keyAliasList.stream()
                .anyMatch(pair ->
                        credentialConfig.getKeyManagerAppId() != null
                                && pair.getFirst().equals(credentialConfig.getKeyManagerAppId())
                                && credentialConfig.getKeyManagerRefId() != null
                                && pair.getLast().equals(credentialConfig.getKeyManagerRefId()));

        if (!isMatch && StringUtils.hasText(credentialConfig.getIssuerId())) {
            isMatch = issuerRepository.findById(credentialConfig.getIssuerId())
                    .map(issuer -> matchesIssuerSigningKeys(credentialConfig, issuer))
                    .orElse(false);
        }

        if (!isMatch) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_APP_REF_NOT_FOUND,
                    "No matching appId and refId found in the key chooser configuration.");
        }
    }

    private void applyIssuerSigningKeys(CredentialConfigurationDTO credentialConfig, Issuer issuer) {
        // mso_mdoc signs with issuer Document Signer (mdocDs*), not LDP DID keys.
        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            return;
        }
        if (!StringUtils.hasText(issuer.getKeyManagerAppId())) {
            return;
        }
        if (!IssuerConstants.DEFAULT_ISSUER_ID.equals(issuer.getIssuerId())) {
            credentialConfig.setKeyManagerAppId(issuer.getKeyManagerAppId());
            credentialConfig.setKeyManagerRefId(issuer.getKeyManagerRefId());
            if (!StringUtils.hasText(credentialConfig.getSignatureAlgo())) {
                credentialConfig.setSignatureAlgo(issuer.getSignatureAlgo());
            }
            if (!StringUtils.hasText(credentialConfig.getSignatureCryptoSuite())) {
                credentialConfig.setSignatureCryptoSuite(issuer.getSignatureCryptoSuite());
            }
            return;
        }
        if (!StringUtils.hasText(credentialConfig.getKeyManagerAppId())) {
            credentialConfig.setKeyManagerAppId(issuer.getKeyManagerAppId());
            credentialConfig.setKeyManagerRefId(issuer.getKeyManagerRefId());
            if (!StringUtils.hasText(credentialConfig.getSignatureAlgo())) {
                credentialConfig.setSignatureAlgo(issuer.getSignatureAlgo());
            }
            if (!StringUtils.hasText(credentialConfig.getSignatureCryptoSuite())) {
                credentialConfig.setSignatureCryptoSuite(issuer.getSignatureCryptoSuite());
            }
        }
    }

    private void validateIssuerCredentialBinding(CredentialConfigurationDTO credentialConfig, Issuer issuer) {
        if (IssuerConstants.DEFAULT_ISSUER_ID.equals(issuer.getIssuerId())) {
            return;
        }
        if (!issuer.getIssuerId().equals(credentialConfig.getIssuerId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "Credential configuration issuerId must match the target issuer: " + issuer.getIssuerId());
        }
        // mso_mdoc uses issuer mdoc DS/IACA PKI; do not require LDP keyManager* binding.
        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            return;
        }
        if (StringUtils.hasText(issuer.getKeyManagerAppId())
                && !issuer.getKeyManagerAppId().equals(credentialConfig.getKeyManagerAppId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "keyManagerAppId must match the onboarded issuer signing keys");
        }
        if (StringUtils.hasText(issuer.getKeyManagerRefId())
                && !issuer.getKeyManagerRefId().equals(credentialConfig.getKeyManagerRefId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "keyManagerRefId must match the onboarded issuer signing keys");
        }
    }

    private boolean matchesIssuerSigningKeys(CredentialConfigurationDTO credentialConfig, Issuer issuer) {
        return StringUtils.hasText(credentialConfig.getKeyManagerAppId())
                && credentialConfig.getKeyManagerAppId().equals(issuer.getKeyManagerAppId())
                && StringUtils.hasText(credentialConfig.getKeyManagerRefId())
                && credentialConfig.getKeyManagerRefId().equals(issuer.getKeyManagerRefId());
    }

    @Override
    public CredentialConfigurationDTO getCredentialConfigurationById(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if (optional.isEmpty()) {
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID,
                    "Configuration not found for the provided ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        if (!credentialConfig.getStatus().equals(Constants.ACTIVE)) {
            throw new CertifyException(ErrorConstants.CONFIG_NOT_ACTIVE, "Configuration is inactive.");
        }

        return credentialConfigMapper.toDto(credentialConfig);
    }

    @Override
    public List<CredentialConfigurationDTO> listCredentialConfigurations(String issuerId) {
        Issuer issuer = issuerResolver.resolve(issuerResolver.resolveIssuerId(issuerId));
        return credentialConfigRepository.findByIssuerIdAndStatus(issuer.getIssuerId(), Constants.ACTIVE).stream()
                .map(credentialConfigMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME,
            key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)",
            condition = "#credentialConfigKeyId != null")
    public CredentialConfigResponse updateCredentialConfiguration(String credentialConfigKeyId,
            CredentialConfigurationDTO credentialConfigurationDTO) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if (optional.isEmpty()) {
            log.warn("Configuration not found for update with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_UPDATE,
                    "Configuration not found for update with ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        Issuer issuer = issuerResolver.resolve(credentialConfig.getIssuerId());
        if (StringUtils.hasText(credentialConfigurationDTO.getIssuerId())
                && !issuer.getIssuerId().equals(credentialConfigurationDTO.getIssuerId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "Cannot change issuerId for an existing credential configuration");
        }
        credentialConfigurationDTO.setIssuerId(issuer.getIssuerId());
        applyIssuerSigningKeys(credentialConfigurationDTO, issuer);
        validateIssuerCredentialBinding(credentialConfigurationDTO, issuer);

        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);

        validateCredentialConfiguration(credentialConfigMapper.toDto(credentialConfig), false);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Updated credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());
        credentialConfigResponse.setIssuerId(savedConfig.getIssuerId());

        return credentialConfigResponse;
    }

    @Override
    @Transactional
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME,
            key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)",
            beforeInvocation = true)
    public String deleteCredentialConfigurationById(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if (optional.isEmpty()) {
            log.warn("Configuration not found for delete with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_DELETE,
                    "Configuration not found for delete with ID: " + credentialConfigKeyId);
        }

        credentialConfigRepository.delete(optional.get());
        log.info("Deleted credential configuration: {}", credentialConfigKeyId);
        return credentialConfigKeyId;
    }

    @Override
    public CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String issuerId, String version) {
        Issuer issuer = issuerResolver.resolve(issuerResolver.resolveIssuerId(issuerId));
        List<CredentialConfig> credentialConfigList = credentialConfigRepository
                .findByIssuerIdAndStatus(issuer.getIssuerId(), Constants.ACTIVE);

        return switch (version) {
            case "latest" -> buildMetadataVD13(credentialConfigList, issuer, version);
            case "vd12" -> buildMetadataVD12(credentialConfigList, issuer, version);
            case "vd11" -> buildMetadataVD11(credentialConfigList, issuer, version);
            default -> throw new CertifyException("UNSUPPORTED_METADATA_VERSION", "Unsupported version: " + version);
        };
    }

    private CredentialIssuerMetadataVD13DTO buildMetadataVD13(List<CredentialConfig> credentialConfigList,
            Issuer issuer, String version) {
        CredentialIssuerMetadataVD13DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD13DTO();
        Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();

        credentialConfigList.forEach(credentialConfig -> {
            CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
            if (credentialConfig.getSignatureCryptoSuite() != null) {
                dto.setCredentialSigningAlgValuesSupported(
                        credentialSigningAlgValuesSupportedMap.get(credentialConfig.getSignatureCryptoSuite()));
            } else {
                dto.setCredentialSigningAlgValuesSupported(
                        Collections.singletonList(credentialConfig.getSignatureAlgo()));
            }
            credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), dto);
        });

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
        populateCommonMetadataFields(credentialIssuerMetadata, issuer, version);
        return credentialIssuerMetadata;
    }

    private CredentialIssuerMetadataVD12DTO buildMetadataVD12(List<CredentialConfig> credentialConfigList,
            Issuer issuer, String version) {
        CredentialIssuerMetadataVD12DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD12DTO();
        Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();

        credentialConfigList.forEach(credentialConfig -> {
            CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
            dto.setCryptographicSuitesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
            credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), dto);
        });

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
        populateCommonMetadataFields(credentialIssuerMetadata, issuer, version);
        return credentialIssuerMetadata;
    }

    private CredentialIssuerMetadataVD11DTO buildMetadataVD11(List<CredentialConfig> credentialConfigList,
            Issuer issuer, String version) {
        CredentialIssuerMetadataVD11DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD11DTO();
        List<CredentialConfigurationSupportedDTO> credentialConfigurationSupportedList = new ArrayList<>();

        credentialConfigList.forEach(credentialConfig -> {
            CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
            dto.setId(credentialConfig.getCredentialConfigKeyId());
            dto.setCryptographicSuitesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
            credentialConfigurationSupportedList.add(dto);
        });

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedList);
        populateCommonMetadataFields(credentialIssuerMetadata, issuer, version);
        return credentialIssuerMetadata;
    }

    private void populateCommonMetadataFields(CredentialIssuerMetadataDTO metadata, Issuer issuer, String version) {
        metadata.setCredentialIssuer(issuer.getCredentialIssuerUrl());
        metadata.setAuthorizationServers(resolveAuthorizationServers(issuer));
        metadata.setCredentialEndpoint(buildCredentialEndpoint(issuer, version));
        metadata.setDisplay(mapIssuerDisplay(issuer));
        if (allowCNonce) {
            metadata.setNonceEndpoint(buildNonceEndpoint(issuer));
        }
    }

    private List<Map<String, String>> mapIssuerDisplay(Issuer issuer) {
        if (issuer.getDisplay() == null || issuer.getDisplay().isEmpty()) {
            return issuerDisplay;
        }
        return issuer.getDisplay().stream()
                .map(display -> {
                    Map<String, String> map = new LinkedHashMap<>();
                    map.put("name", display.getName());
                    map.put("locale", display.getLocale());
                    return map;
                })
                .collect(Collectors.toList());
    }

    private String buildNonceEndpoint(Issuer issuer) {
        return issuer.getCredentialIssuerUrl() + "/nonce";
    }

    private List<String> resolveAuthorizationServers(Issuer issuer) {
        Set<String> allServers = new LinkedHashSet<>();

        if (issuer.getAuthorizationServers() != null) {
            issuer.getAuthorizationServers().stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(allServers::add);
        }

        if (allServers.isEmpty() && StringUtils.hasText(authUrl)) {
            Arrays.stream(authUrl.split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .forEach(allServers::add);
        }

        if (authorizationServerMapping != null) {
            authorizationServerMapping.values().stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(allServers::add);
        }

        if (allServers.isEmpty()) {
            return Collections.singletonList(authUrl);
        }

        return new ArrayList<>(allServers);
    }

    private String buildCredentialEndpoint(Issuer issuer, String version) {
        if ("latest".equals(version)) {
            return issuer.getCredentialIssuerUrl() + "/issuance/credential";
        }
        return issuer.getCredentialIssuerUrl() + "/issuance/" + version + "/credential";
    }

    private CredentialConfigurationSupportedDTO mapToSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO credentialConfigurationSupported = new CredentialConfigurationSupportedDTO();
        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
        credentialConfigurationSupported.setFormat(credentialConfigurationDTO.getCredentialFormat());
        credentialConfigurationSupported.setScope(credentialConfigurationDTO.getScope());
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(
                credentialConfig.getCryptographicBindingMethodsSupported());
        credentialConfigurationSupported.setProofTypesSupported(credentialConfig.getProofTypesSupported());
        credentialConfigurationSupported.setDisplay(credentialConfigurationDTO.getMetaDataDisplay());
        credentialConfigurationSupported.setOrder(credentialConfigurationDTO.getDisplayOrder());

        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())) {
            CredentialDefinition credentialDefinition = new CredentialDefinition();
            credentialDefinition.setType(credentialConfigurationDTO.getCredentialTypes());
            credentialDefinition.setContext(credentialConfigurationDTO.getContextURLs());
            if (credentialConfig.getCredentialSubject() != null) {
                credentialDefinition.setCredentialSubject(new HashMap<>(credentialConfig.getCredentialSubject()));
            }
            credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);
        } else if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            if (credentialConfig.getMsoMdocClaims() != null) {
                credentialConfigurationSupported.setClaims(new HashMap<>(credentialConfig.getMsoMdocClaims()));
            }
            credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
        } else if (VCFormats.VC_SD_JWT.equals(credentialConfig.getCredentialFormat())) {
            if (credentialConfig.getSdJwtClaims() != null) {
                credentialConfigurationSupported.setClaims(new HashMap<>(credentialConfig.getSdJwtClaims()));
            }
            credentialConfigurationSupported.setVct(credentialConfig.getSdJwtVct());
        }

        return credentialConfigurationSupported;
    }
}
