package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.validation.IssuerIdValidator;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.mdoc.MdocPkiRefs;
import io.mosip.certify.mdoc.MdocPkiService;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.DidWebUtil;
import io.mosip.certify.utils.IssuerMapper;
import io.mosip.certify.utils.KeyManagerAppIdUtil;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.repository.KeyPolicyRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Service
public class IssuerOnboardingService {

    @Autowired
    private IssuerRepository issuerRepository;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyPolicyRepository keyPolicyRepository;

    @Autowired
    private IssuerMapper issuerMapper;

    @Autowired
    private MdocPkiService mdocPkiService;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    @Value("${mosip.certify.identifier}")
    private String defaultIdentifier;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.authorization.url}")
    private String authUrl;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    @Value("${mosip.certify.issuer.key-policy.validity-days:1095}")
    private int keyPolicyValidityDays;

    @Value("${mosip.certify.issuer.key-policy.pre-expire-days:60}")
    private int keyPolicyPreExpireDays;

    @Transactional
    public IssuerOnboardingResponse onboard(IssuerOnboardingRequest request) {
        validateOnboardingRequest(request);

        if (issuerRepository.existsByIssuerId(request.getIssuerId())) {
            throw new CertifyException(ErrorConstants.ISSUER_ALREADY_EXISTS,
                    "Issuer already exists: " + request.getIssuerId());
        }

        IssuerSigningConfigDTO signingConfig = request.getSigningConfig();
        validateSigningConfig(signingConfig);

        String keyManagerAppId = buildKeyManagerAppId(request.getIssuerId(), signingConfig.getSignatureAlgo());
        List<String> keyRefs = resolveKeyRefs(signingConfig);
        String keyManagerRefId = keyRefs.getLast();

        MdocPkiRefs mdocPkiRefs;
        try {
            ensureKeyPolicy(keyManagerAppId);
            generateIssuerKeys(keyManagerAppId, signingConfig.getSignatureAlgo(), keyManagerRefId);
            mdocPkiRefs = mdocPkiService.provision(request.getIssuerId());
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to generate keys for issuer {}", request.getIssuerId(), e);
            throw new CertifyException(ErrorConstants.ISSUER_KEY_GENERATION_FAILED,
                    "Key generation failed for issuer: " + request.getIssuerId());
        }

        String credentialIssuerUrl = domainUrl + servletPath;
        String identifier = defaultIdentifier;
        String didUrl = resolveDidUrl(request);

        Issuer issuer = new Issuer();
        issuer.setIssuerId(request.getIssuerId());
        issuer.setCredentialIssuerUrl(credentialIssuerUrl);
        issuer.setIdentifier(identifier);
        issuer.setDidUrl(didUrl);
        issuer.setDisplay(issuerMapper.mapDisplayToEntity(request.getDisplay()));
        issuer.setAuthorizationServers(resolveAuthorizationServers(request.getAuthorizationServers()));
        issuer.setKeyManagerAppId(keyManagerAppId);
        issuer.setKeyManagerRefId(keyManagerRefId);
        issuer.setSignatureCryptoSuite(signingConfig.getSignatureCryptoSuite());
        issuer.setSignatureAlgo(signingConfig.getSignatureAlgo());
        issuer.setMdocIacaAppId(mdocPkiRefs.iacaAppId());
        issuer.setMdocIacaRefId(mdocPkiRefs.iacaRefId());
        issuer.setMdocDsAppId(mdocPkiRefs.dsAppId());
        issuer.setMdocDsRefId(mdocPkiRefs.dsRefId());
        issuer.setStatus(Constants.ACTIVE);
        issuer.setCreatedTimes(LocalDateTime.now());

        issuerRepository.save(issuer);
        log.info("Onboarded issuer: {}", issuer.getIssuerId());

        return buildOnboardingResponse(issuer);
    }

    private void validateOnboardingRequest(IssuerOnboardingRequest request) {
        String issuerId = IssuerIdValidator.normalize(request.getIssuerId());
        if (!IssuerIdValidator.isValid(issuerId)) {
            throw new CertifyException(ErrorConstants.INVALID_ISSUER_ID,
                    "issuerId must match pattern: " + IssuerConstants.ISSUER_ID_PATTERN
                            + " (received: " + abbreviateForError(request.getIssuerId()) + ")");
        }
        request.setIssuerId(issuerId);
        if (IssuerConstants.DEFAULT_ISSUER_ID.equals(issuerId)) {
            throw new CertifyException(ErrorConstants.INVALID_ISSUER_ID,
                    "Cannot onboard reserved issuerId: default");
        }
    }

    private String abbreviateForError(String issuerId) {
        if (issuerId == null) {
            return "null";
        }
        String sanitized = issuerId.replaceAll("[\\r\\n]", " ");
        return sanitized.length() <= 128 ? sanitized : sanitized.substring(0, 125) + "...";
    }

    private void validateSigningConfig(IssuerSigningConfigDTO signingConfig) {
        if (!credentialSigningAlgValuesSupportedMap.containsKey(signingConfig.getSignatureCryptoSuite())) {
            throw new CertifyException(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE,
                    "Unsupported signature crypto suite: " + signingConfig.getSignatureCryptoSuite());
        }
        List<String> allowedAlgos = credentialSigningAlgValuesSupportedMap.get(signingConfig.getSignatureCryptoSuite());
        if (!allowedAlgos.contains(signingConfig.getSignatureAlgo())) {
            throw new CertifyException(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO,
                    "Signature algorithm not supported for crypto suite: " + signingConfig.getSignatureCryptoSuite());
        }
        if (!keyAliasMapper.containsKey(signingConfig.getSignatureAlgo())) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND,
                    "No key configuration for signature algorithm: " + signingConfig.getSignatureAlgo());
        }
    }

    private List<String> resolveKeyRefs(IssuerSigningConfigDTO signingConfig) {
        List<List<String>> aliases = keyAliasMapper.get(signingConfig.getSignatureAlgo());
        if (aliases == null || aliases.isEmpty()) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND,
                    "No key alias mapping for: " + signingConfig.getSignatureAlgo());
        }
        return aliases.getFirst();
    }

    private void ensureKeyPolicy(String appId) {
        if (keyPolicyRepository.findByApplicationId(appId).isPresent()) {
            return;
        }
        KeyPolicy policy = new KeyPolicy();
        policy.setApplicationId(appId);
        policy.setValidityInDays(keyPolicyValidityDays);
        policy.setPreExpireDays(keyPolicyPreExpireDays);
        policy.setAccessAllowed("NA");
        policy.setActive(true);
        policy.setCreatedBy("certify-issuer-onboarding");
        policy.setCreatedtimes(LocalDateTime.now());
        keyPolicyRepository.save(policy);
        log.info("Registered key policy for issuer app id: {}", appId);
    }

    private String buildKeyManagerAppId(String issuerId, String signatureAlgo) {
        String algoSuffix = switch (signatureAlgo) {
            case "EdDSA" -> "ED25519";
            case "RS256" -> "RSA";
            case "ES256" -> "EC_R1";
            case "ES256K" -> "EC_K1";
            default -> signatureAlgo.toUpperCase(Locale.ROOT);
        };
        return KeyManagerAppIdUtil.buildAppId(IssuerConstants.KEY_APP_ID_PREFIX, issuerId, algoSuffix);
    }

    private void generateIssuerKeys(String appId, String signatureAlgo, String refId) {
        KeyPairGenerateRequestDto request = new KeyPairGenerateRequestDto();
        request.setApplicationId(appId);
        request.setForce(false);

        switch (signatureAlgo) {
            case "EdDSA" -> {
                request.setReferenceId(Constants.EMPTY_REF_ID);
                keymanagerService.generateMasterKey("certificate", request);
                KeyPairGenerateRequestDto ed25519Req = new KeyPairGenerateRequestDto();
                ed25519Req.setApplicationId(appId);
                ed25519Req.setReferenceId(Constants.ED25519_REF_ID);
                ed25519Req.setForce(false);
                keymanagerService.generateECSignKey("certificate", ed25519Req);
            }
            case "RS256" -> {
                request.setReferenceId(Constants.EMPTY_REF_ID);
                keymanagerService.generateMasterKey("certificate", request);
            }
            case "ES256K", "ES256" -> {
                request.setReferenceId(refId);
                keymanagerService.generateECSignKey("certificate", request);
            }
            default -> throw new CertifyException(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO,
                    "Unsupported signature algorithm for key generation: " + signatureAlgo);
        }
    }

    private String resolveDidUrl(IssuerOnboardingRequest request) {
        if (StringUtils.isNotBlank(request.getDidUrl())) {
            return request.getDidUrl();
        }
        return DidWebUtil.buildIssuerDidWebIdentifier(domainUrl, servletPath, request.getIssuerId());
    }

    private List<String> resolveAuthorizationServers(List<String> requested) {
        if (requested != null && !requested.isEmpty()) {
            return requested;
        }
        if (StringUtils.isBlank(authUrl)) {
            return Collections.emptyList();
        }
        return Arrays.stream(authUrl.split(","))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .toList();
    }

    private IssuerOnboardingResponse buildOnboardingResponse(Issuer issuer) {
        IssuerOnboardingResponse response = new IssuerOnboardingResponse();
        response.setIssuerId(issuer.getIssuerId());
        response.setStatus(issuer.getStatus());
        response.setCredentialIssuerUrl(issuer.getCredentialIssuerUrl());
        response.setIdentifier(issuer.getIdentifier());
        response.setDidUrl(issuer.getDidUrl());
        response.setKeyManagerAppId(issuer.getKeyManagerAppId());
        response.setKeyManagerRefId(issuer.getKeyManagerRefId());
        response.setMdocIacaAppId(issuer.getMdocIacaAppId());
        response.setMdocIacaRefId(issuer.getMdocIacaRefId());
        response.setMdocDsAppId(issuer.getMdocDsAppId());
        response.setMdocDsRefId(issuer.getMdocDsRefId());

        String base = domainUrl + servletPath;
        Map<String, String> wellKnown = new LinkedHashMap<>();
        wellKnown.put("openidCredentialIssuer",
                base + "/.well-known/openid-credential-issuer?issuerId=" + issuer.getIssuerId());
        wellKnown.put("didJson", DidWebUtil.buildIssuerDidDocumentUrl(domainUrl, servletPath, issuer.getIssuerId()));
        response.setWellKnownEndpoints(wellKnown);
        return response;
    }
}
