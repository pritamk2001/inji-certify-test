-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : issuer
-- Purpose    : Credential Issuer registry for multi-issuer support
-- -------------------------------------------------------------------------------------------------

CREATE TABLE issuer (
    issuer_id               VARCHAR(64)   NOT NULL,
    credential_issuer_url   VARCHAR(512)  NOT NULL,
    did_url                 VARCHAR(512)  NOT NULL,
    identifier              VARCHAR(512)  NOT NULL,
    display                 JSONB         NOT NULL,
    authorization_servers   JSONB,
    key_manager_app_id      VARCHAR(36),
    key_manager_ref_id      VARCHAR(128),
    signature_crypto_suite  VARCHAR(64),
    signature_algo          VARCHAR(32),
    mdoc_iaca_app_id        VARCHAR(36),
    mdoc_iaca_ref_id        VARCHAR(128),
    mdoc_ds_app_id          VARCHAR(36),
    mdoc_ds_ref_id          VARCHAR(128),
    status                  VARCHAR(16)   NOT NULL DEFAULT 'ACTIVE',
    cr_dtimes               TIMESTAMP     NOT NULL DEFAULT NOW(),
    upd_dtimes              TIMESTAMP,
    CONSTRAINT pk_issuer_id PRIMARY KEY (issuer_id)
);

COMMENT ON TABLE issuer IS 'Issuer: Registry of credential issuers onboarded at runtime.';
COMMENT ON COLUMN issuer.issuer_id IS 'Issuer ID: Unique slug identifying the issuer.';
COMMENT ON COLUMN issuer.credential_issuer_url IS 'Credential Issuer URL: OID4VCI credential_issuer identifier.';
COMMENT ON COLUMN issuer.did_url IS 'DID URL: Decentralized identifier for the issuer.';
COMMENT ON COLUMN issuer.identifier IS 'Identifier: VC iss claim and proof aud validation value.';
COMMENT ON COLUMN issuer.display IS 'Display: Localized issuer display metadata.';
COMMENT ON COLUMN issuer.authorization_servers IS 'Authorization Servers: OAuth authorization server URLs for this issuer.';
COMMENT ON COLUMN issuer.key_manager_app_id IS 'Key Manager App ID: MOSIP keymanager application id for signing keys.';
COMMENT ON COLUMN issuer.key_manager_ref_id IS 'Key Manager Ref ID: MOSIP keymanager reference id for signing keys.';
COMMENT ON COLUMN issuer.signature_crypto_suite IS 'Signature Crypto Suite: VC proof crypto suite for this issuer.';
COMMENT ON COLUMN issuer.signature_algo IS 'Signature Algorithm: VC signing algorithm for this issuer.';
COMMENT ON COLUMN issuer.mdoc_iaca_app_id IS 'mDoc IACA App ID: Keymanager application id for issuer IACA key.';
COMMENT ON COLUMN issuer.mdoc_iaca_ref_id IS 'mDoc IACA Ref ID: Keymanager reference id for issuer IACA key.';
COMMENT ON COLUMN issuer.mdoc_ds_app_id IS 'mDoc DS App ID: Keymanager application id for Document Signer key.';
COMMENT ON COLUMN issuer.mdoc_ds_ref_id IS 'mDoc DS Ref ID: Keymanager reference id for Document Signer key.';
COMMENT ON COLUMN issuer.status IS 'Status: Issuer lifecycle status (ACTIVE or INACTIVE).';
