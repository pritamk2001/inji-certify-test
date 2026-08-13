/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.repository.IssuerRepository;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Optional batch rotation of near-expiry Document Signer certificates.
 * <p>
 * Primary / recommended path is on-demand (ROOT-style) rotation via
 * {@link MdocPkiService#ensureDocumentSignerCurrent(Issuer)} during mdoc signing.
 * Enable this scheduler only if you want proactive rotation while no issuance traffic occurs.
 */
@Slf4j
@Component
public class MdocDsRotationScheduler {

    @Autowired
    private IssuerRepository issuerRepository;

    @Autowired
    private MdocPkiService mdocPkiService;

    /**
     * Disabled by default — DS rotates on use like KeyManager ROOT keys.
     * Set {@code mosip.certify.mdoc.ds.rotation.enabled=true} for optional proactive batch rotation.
     */
    @Value("${mosip.certify.mdoc.ds.rotation.enabled:false}")
    private boolean rotationEnabled;

    @Scheduled(cron = "${mosip.certify.mdoc.ds.rotation.cron:0 0 2 * * *}")
    @SchedulerLock(
            name = "rotateMdocDocumentSigners",
            lockAtMostFor = "${mosip.certify.mdoc.ds.rotation.lock-at-most-for:30m}",
            lockAtLeastFor = "${mosip.certify.mdoc.ds.rotation.lock-at-least-for:1m}"
    )
    public void rotateDueDocumentSigners() {
        LockAssert.assertLocked();
        if (!rotationEnabled) {
            log.debug("mDoc DS batch rotation scheduler is disabled (on-demand rotation is primary)");
            return;
        }

        List<Issuer> issuers = issuerRepository.findByStatus(Constants.ACTIVE);
        int rotated = 0;
        int failed = 0;
        for (Issuer issuer : issuers) {
            if (StringUtils.isBlank(issuer.getMdocDsAppId())) {
                continue;
            }
            try {
                if (!mdocPkiService.isDsRotationDue(issuer)) {
                    continue;
                }
                log.info("Batch-rotating mdoc Document Signer for issuer {}", issuer.getIssuerId());
                mdocPkiService.rotateDocumentSigner(issuer);
                rotated++;
            } catch (Exception e) {
                failed++;
                log.error("Failed to rotate mdoc DS for issuer {}", issuer.getIssuerId(), e);
            }
        }
        if (rotated > 0 || failed > 0) {
            log.info("mDoc DS batch rotation finished: rotated={}, failed={}", rotated, failed);
        }
    }
}
