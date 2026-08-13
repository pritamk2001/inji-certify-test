package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.core.dto.IssuerDTO;
import io.mosip.certify.core.dto.IssuerUpdateRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.mdoc.MdocPkiService;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.IssuerMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
public class IssuerServiceImpl {

    @Autowired
    private IssuerRepository issuerRepository;

    @Autowired
    private IssuerMapper issuerMapper;

    @Autowired
    private MdocPkiService mdocPkiService;

    public List<IssuerDTO> listIssuers() {
        return issuerRepository.findAll().stream()
                .map(issuerMapper::toDto)
                .toList();
    }

    public IssuerDTO getIssuer(String issuerId) {
        Issuer issuer = issuerRepository.findById(issuerId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.ISSUER_NOT_FOUND,
                        "Issuer not found: " + issuerId));
        return issuerMapper.toDto(issuer);
    }

    /**
     * Returns the IACA PEM for verifier trust-store installation (ISO 18013-5 dissemination).
     */
    public CertificateResponseDTO getMdocIacaCertificate(String issuerId) {
        Issuer issuer = issuerRepository.findById(issuerId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.ISSUER_NOT_FOUND,
                        "Issuer not found: " + issuerId));
        CertificateResponseDTO response = new CertificateResponseDTO();
        response.setKeyId(issuer.getMdocIacaAppId());
        response.setCertificateData(mdocPkiService.exportIacaCertificatePem(issuer));
        return response;
    }

    @Transactional
    public IssuerDTO updateIssuer(String issuerId, IssuerUpdateRequest request) {
        Issuer issuer = issuerRepository.findById(issuerId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.ISSUER_NOT_FOUND,
                        "Issuer not found: " + issuerId));

        if (request.getDisplay() != null) {
            issuer.setDisplay(issuerMapper.mapDisplayToEntity(request.getDisplay()));
        }
        if (request.getAuthorizationServers() != null) {
            issuer.setAuthorizationServers(request.getAuthorizationServers());
        }
        if (request.getStatus() != null) {
            if (!Constants.ACTIVE.equals(request.getStatus()) && !Constants.INACTIVE.equals(request.getStatus())) {
                throw new CertifyException(ErrorConstants.INVALID_ISSUER_ID,
                        "Invalid status. Allowed values: active, inactive");
            }
            issuer.setStatus(request.getStatus());
        }
        issuer.setUpdatedTimes(LocalDateTime.now());
        issuerRepository.save(issuer);
        log.info("Updated issuer: {}", issuerId);
        return issuerMapper.toDto(issuer);
    }

    @Transactional
    public IssuerDTO deactivateIssuer(String issuerId) {
        Issuer issuer = issuerRepository.findById(issuerId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.ISSUER_NOT_FOUND,
                        "Issuer not found: " + issuerId));
        issuer.setStatus(Constants.INACTIVE);
        issuer.setUpdatedTimes(LocalDateTime.now());
        issuerRepository.save(issuer);
        log.info("Deactivated issuer: {}", issuerId);
        return issuerMapper.toDto(issuer);
    }
}
