package io.mosip.certify.controller;

import io.mosip.certify.core.dto.*;
import io.mosip.certify.services.IssuerOnboardingService;
import io.mosip.certify.services.IssuerServiceImpl;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/issuers")
public class IssuerController {

    @Autowired
    private IssuerOnboardingService issuerOnboardingService;

    @Autowired
    private IssuerServiceImpl issuerService;

    @PostMapping(produces = "application/json")
    public ResponseEntity<IssuerOnboardingResponse> onboardIssuer(
            @Valid @RequestBody IssuerOnboardingRequest request) {
        IssuerOnboardingResponse response = issuerOnboardingService.onboard(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @GetMapping(produces = "application/json")
    public ResponseEntity<List<IssuerDTO>> listIssuers() {
        return ResponseEntity.ok(issuerService.listIssuers());
    }

    @GetMapping(value = "/{issuerId}", produces = "application/json")
    public ResponseEntity<IssuerDTO> getIssuer(@PathVariable String issuerId) {
        return ResponseEntity.ok(issuerService.getIssuer(issuerId));
    }

    /**
     * Exports the issuer IACA root certificate (PEM) for mdoc verifiers to install as a trust anchor
     * per ISO/IEC 18013-5 out-of-band dissemination.
     */
    @GetMapping(value = "/{issuerId}/mdoc/iaca-certificate", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateResponseDTO> getMdocIacaCertificate(@PathVariable String issuerId) {
        return ResponseEntity.ok(issuerService.getMdocIacaCertificate(issuerId));
    }

    @PutMapping(value = "/{issuerId}", produces = "application/json")
    public ResponseEntity<IssuerDTO> updateIssuer(
            @PathVariable String issuerId,
            @Valid @RequestBody IssuerUpdateRequest request) {
        return ResponseEntity.ok(issuerService.updateIssuer(issuerId, request));
    }

    @DeleteMapping(value = "/{issuerId}", produces = "application/json")
    public ResponseEntity<IssuerDTO> deactivateIssuer(@PathVariable String issuerId) {
        return ResponseEntity.ok(issuerService.deactivateIssuer(issuerId));
    }
}
