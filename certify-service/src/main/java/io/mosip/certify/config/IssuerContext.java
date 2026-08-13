package io.mosip.certify.config;

import io.mosip.certify.entity.Issuer;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

@Component
@RequestScope
public class IssuerContext {

    private Issuer currentIssuer;

    public void setCurrent(Issuer issuer) {
        this.currentIssuer = issuer;
    }

    public Issuer getCurrent() {
        return currentIssuer;
    }

    public String getIdentifier() {
        return currentIssuer != null ? currentIssuer.getIdentifier() : null;
    }

    public String getDidUrl() {
        return currentIssuer != null ? currentIssuer.getDidUrl() : null;
    }

    public String getIssuerId() {
        return currentIssuer != null ? currentIssuer.getIssuerId() : null;
    }
}
