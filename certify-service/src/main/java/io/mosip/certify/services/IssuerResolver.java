package io.mosip.certify.services;

import io.mosip.certify.config.IssuerContext;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.validation.IssuerIdValidator;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.repository.IssuerRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class IssuerResolver {

    @Autowired
    private IssuerRepository issuerRepository;

    @Autowired
    private IssuerContext issuerContext;

    public Issuer resolve(String issuerId) {
        String resolvedId = IssuerIdValidator.normalize(
                StringUtils.defaultIfBlank(issuerId, IssuerConstants.DEFAULT_ISSUER_ID));
        if (!IssuerIdValidator.isValid(resolvedId)) {
            throw new CertifyException(ErrorConstants.INVALID_ISSUER_ID,
                    "Invalid issuerId format: " + resolvedId);
        }

        Issuer issuer = issuerRepository.findById(resolvedId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.ISSUER_NOT_FOUND,
                        "Issuer not found: " + resolvedId));

        if (!Constants.ACTIVE.equals(issuer.getStatus())) {
            throw new CertifyException(ErrorConstants.ISSUER_INACTIVE,
                    "Issuer is inactive: " + resolvedId);
        }

        issuerContext.setCurrent(issuer);
        return issuer;
    }

    public String resolveIssuerId(String issuerId) {
        return StringUtils.defaultIfBlank(issuerId, IssuerConstants.DEFAULT_ISSUER_ID);
    }
}
