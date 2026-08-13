package io.mosip.certify.config;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.mdoc.MdocPkiRefs;
import io.mosip.certify.mdoc.MdocPkiService;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.IssuerMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Component
@Order(100)
public class IssuerBootstrapConfig implements ApplicationRunner {

    @Autowired
    private IssuerRepository issuerRepository;

    @Autowired
    private IssuerMapper issuerMapper;

    @Autowired
    private MdocPkiService mdocPkiService;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    @Value("${mosip.certify.identifier}")
    private String identifier;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.data-provider-plugin.did-url}")
    private String didUrl;

    @Value("${mosip.certify.authorization.url:}")
    private String authUrl;

    @Value("#{${mosip.certify.credential-config.issuer.display:[]}}")
    private List<Map<String, Object>> issuerDisplay;

    @Override
    public void run(ApplicationArguments args) {
        Optional<Issuer> existing = issuerRepository.findById(IssuerConstants.DEFAULT_ISSUER_ID);
        if (existing.isPresent()) {
            updateDefaultIssuerFromProperties(existing.get());
            return;
        }

        log.info("Seeding default issuer from application properties");
        Issuer issuer = new Issuer();
        issuer.setIssuerId(IssuerConstants.DEFAULT_ISSUER_ID);
        issuer.setCredentialIssuerUrl(domainUrl + servletPath);
        issuer.setIdentifier(identifier);
        issuer.setDidUrl(didUrl);
        issuer.setDisplay(mapDisplayFromProperties());
        issuer.setAuthorizationServers(resolveAuthServers());
        issuer.setKeyManagerAppId(Constants.CERTIFY_VC_SIGN_ED25519);
        issuer.setKeyManagerRefId(Constants.ED25519_REF_ID);
        issuer.setSignatureCryptoSuite("Ed25519Signature2020");
        issuer.setSignatureAlgo("EdDSA");
        issuer.setStatus(Constants.ACTIVE);
        issuer.setCreatedTimes(LocalDateTime.now());
        ensureDefaultMdocPki(issuer);
        issuerRepository.save(issuer);
        log.info("Default issuer seeded successfully");
    }

    private void updateDefaultIssuerFromProperties(Issuer issuer) {
        issuer.setCredentialIssuerUrl(domainUrl + servletPath);
        issuer.setIdentifier(identifier);
        issuer.setDidUrl(didUrl);
        if (issuer.getDisplay() == null || issuer.getDisplay().isEmpty()) {
            issuer.setDisplay(mapDisplayFromProperties());
        }
        if (issuer.getAuthorizationServers() == null || issuer.getAuthorizationServers().isEmpty()) {
            issuer.setAuthorizationServers(resolveAuthServers());
        }
        ensureDefaultMdocPki(issuer);
        issuer.setUpdatedTimes(LocalDateTime.now());
        issuerRepository.save(issuer);
    }

    private void ensureDefaultMdocPki(Issuer issuer) {
        if (StringUtils.isNotBlank(issuer.getMdocIacaAppId()) && StringUtils.isNotBlank(issuer.getMdocDsAppId())) {
            return;
        }
        try {
            MdocPkiRefs refs = mdocPkiService.provision(IssuerConstants.DEFAULT_ISSUER_ID);
            issuer.setMdocIacaAppId(refs.iacaAppId());
            issuer.setMdocIacaRefId(refs.iacaRefId());
            issuer.setMdocDsAppId(refs.dsAppId());
            issuer.setMdocDsRefId(refs.dsRefId());
            log.info("Provisioned mdoc IACA/DS for default issuer");
        } catch (Exception e) {
            log.error("Failed to provision mdoc IACA/DS for default issuer; continuing without mdoc KeyManager refs", e);
        }
    }

    private List<String> resolveAuthServers() {
        if (authUrl == null || authUrl.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(authUrl.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private List<io.mosip.certify.entity.attributes.MetaDataDisplay> mapDisplayFromProperties() {
        if (issuerDisplay == null || issuerDisplay.isEmpty()) {
            return Collections.emptyList();
        }
        List<io.mosip.certify.core.dto.MetaDataDisplayDTO> dtos = new ArrayList<>();
        for (Map<String, Object> item : issuerDisplay) {
            io.mosip.certify.core.dto.MetaDataDisplayDTO dto = new io.mosip.certify.core.dto.MetaDataDisplayDTO();
            dto.setName((String) item.get("name"));
            dto.setLocale((String) item.get("locale"));
            if (item.get("logo") instanceof Map<?, ?> logo) {
                io.mosip.certify.core.dto.MetaDataDisplayDTO.Logo logoDto =
                        new io.mosip.certify.core.dto.MetaDataDisplayDTO.Logo();
                logoDto.setUrl((String) logo.get("url"));
                if (logo.get("url") == null) {
                    logoDto.setUrl((String) logo.get("uri"));
                }
                logoDto.setAltText((String) logo.get("alt_text"));
                dto.setLogo(logoDto);
            }
            dtos.add(dto);
        }
        return issuerMapper.mapDisplayToEntity(dtos);
    }
}
