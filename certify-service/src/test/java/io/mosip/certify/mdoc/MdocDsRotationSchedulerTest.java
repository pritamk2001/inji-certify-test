/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.repository.IssuerRepository;
import net.javacrumbs.shedlock.core.LockAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MdocDsRotationSchedulerTest {

    @Mock
    private IssuerRepository issuerRepository;

    @Mock
    private MdocPkiService mdocPkiService;

    @InjectMocks
    private MdocDsRotationScheduler scheduler;

    @Before
    public void setUp() {
        LockAssert.TestHelper.makeAllAssertsPass(true);
        ReflectionTestUtils.setField(scheduler, "rotationEnabled", true);
    }

    @Test
    public void rotateDueDocumentSigners_RotatesOnlyDueIssuers() {
        Issuer due = new Issuer();
        due.setIssuerId("due");
        due.setMdocDsAppId("CERTIFY_DS_DUE");

        Issuer fresh = new Issuer();
        fresh.setIssuerId("fresh");
        fresh.setMdocDsAppId("CERTIFY_DS_FRESH");

        Issuer noMdoc = new Issuer();
        noMdoc.setIssuerId("nomdoc");

        when(issuerRepository.findByStatus(Constants.ACTIVE)).thenReturn(List.of(due, fresh, noMdoc));
        when(mdocPkiService.isDsRotationDue(due)).thenReturn(true);
        when(mdocPkiService.isDsRotationDue(fresh)).thenReturn(false);

        scheduler.rotateDueDocumentSigners();

        verify(mdocPkiService).rotateDocumentSigner(due);
        verify(mdocPkiService, never()).rotateDocumentSigner(fresh);
        verify(mdocPkiService, never()).rotateDocumentSigner(noMdoc);
    }

    @Test
    public void rotateDueDocumentSigners_Disabled_DoesNothing() {
        ReflectionTestUtils.setField(scheduler, "rotationEnabled", false);
        scheduler.rotateDueDocumentSigners();
        verify(issuerRepository, never()).findByStatus(any());
    }
}
