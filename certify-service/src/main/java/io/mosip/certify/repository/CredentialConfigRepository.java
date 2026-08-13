package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.List;

@Repository
public interface CredentialConfigRepository extends JpaRepository<CredentialConfig, String> {
    Optional<CredentialConfig> findByCredentialFormatAndSdJwtVct(String credentialFormat, String sdJwtVct);
    Optional<CredentialConfig> findByCredentialFormatAndDocType(String credentialFormat, String docType);
    Optional<CredentialConfig> findByCredentialFormatAndCredentialTypeAndContext(String credentialFormat, String credentialType, String context);
    Optional<CredentialConfig> findByCredentialConfigKeyId(String credentialConfigKeyID);

    List<CredentialConfig> findByIssuerIdAndStatus(String issuerId, String status);

    Optional<CredentialConfig> findByIssuerIdAndCredentialFormatAndCredentialTypeAndContext(
            String issuerId, String credentialFormat, String credentialType, String context);

    Optional<CredentialConfig> findByIssuerIdAndCredentialFormatAndDocType(
            String issuerId, String credentialFormat, String docType);

    Optional<CredentialConfig> findByIssuerIdAndCredentialFormatAndSdJwtVct(
            String issuerId, String credentialFormat, String sdJwtVct);
}

