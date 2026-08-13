package io.mosip.certify.repository;

import io.mosip.certify.entity.Issuer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IssuerRepository extends JpaRepository<Issuer, String> {

    Optional<Issuer> findByIssuerIdAndStatus(String issuerId, String status);

    List<Issuer> findByStatus(String status);

    boolean existsByIssuerId(String issuerId);

    Optional<Issuer> findByDidUrl(String didUrl);
}
