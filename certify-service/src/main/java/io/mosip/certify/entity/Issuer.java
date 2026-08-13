package io.mosip.certify.entity;

import io.mosip.certify.entity.attributes.MetaDataDisplay;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Entity
@NoArgsConstructor
@Table(name = "issuer")
public class Issuer {

    @Id
    @Column(name = "issuer_id", nullable = false, updatable = false, length = 64)
    private String issuerId;

    @NotNull
    @Column(name = "credential_issuer_url", nullable = false, length = 512)
    private String credentialIssuerUrl;

    @NotNull
    @Column(name = "did_url", nullable = false, length = 512)
    private String didUrl;

    @NotNull
    @Column(name = "identifier", nullable = false, length = 512)
    private String identifier;

    @NotNull
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "display", columnDefinition = "jsonb", nullable = false)
    private List<MetaDataDisplay> display;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "authorization_servers", columnDefinition = "jsonb")
    private List<String> authorizationServers;

    @Column(name = "key_manager_app_id", length = 36)
    private String keyManagerAppId;

    @Column(name = "key_manager_ref_id", length = 128)
    private String keyManagerRefId;

    @Column(name = "signature_crypto_suite", length = 64)
    private String signatureCryptoSuite;

    @Column(name = "signature_algo", length = 32)
    private String signatureAlgo;

    @Column(name = "mdoc_iaca_app_id", length = 36)
    private String mdocIacaAppId;

    @Column(name = "mdoc_iaca_ref_id", length = 128)
    private String mdocIacaRefId;

    @Column(name = "mdoc_ds_app_id", length = 36)
    private String mdocDsAppId;

    @Column(name = "mdoc_ds_ref_id", length = 128)
    private String mdocDsRefId;

    @NotNull
    @Column(name = "status", nullable = false, length = 16)
    private String status;

    @NotNull
    @Column(name = "cr_dtimes", nullable = false)
    private LocalDateTime createdTimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;
}
