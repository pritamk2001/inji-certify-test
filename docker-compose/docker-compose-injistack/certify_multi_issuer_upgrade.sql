-- Idempotent multi-issuer migration for existing injistack PostgreSQL volumes.
-- Safe to re-run on every docker compose up.

\c inji_certify postgres
SET search_path TO certify,pg_catalog,public;

CREATE TABLE IF NOT EXISTS certify.issuer (
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
    status                  VARCHAR(16)   NOT NULL DEFAULT 'active',
    cr_dtimes               TIMESTAMP     NOT NULL DEFAULT NOW(),
    upd_dtimes              TIMESTAMP,
    CONSTRAINT pk_issuer_id PRIMARY KEY (issuer_id)
);

ALTER TABLE certify.issuer ADD COLUMN IF NOT EXISTS mdoc_iaca_app_id VARCHAR(36);
ALTER TABLE certify.issuer ADD COLUMN IF NOT EXISTS mdoc_iaca_ref_id VARCHAR(128);
ALTER TABLE certify.issuer ADD COLUMN IF NOT EXISTS mdoc_ds_app_id VARCHAR(36);
ALTER TABLE certify.issuer ADD COLUMN IF NOT EXISTS mdoc_ds_ref_id VARCHAR(128);

INSERT INTO certify.issuer (
    issuer_id, credential_issuer_url, did_url, identifier, display,
    authorization_servers, key_manager_app_id, key_manager_ref_id,
    signature_crypto_suite, signature_algo, status, cr_dtimes
) VALUES (
    'default',
    'http://certify:8090/v1/certify',
    'did:web:8398-2405-201-1029-3025-e142-9ad3-e1f2-f543.ngrok-free.app',
    'http://certify:8090',
    '[{"name": "Farmer Issuer", "locale": "en"}]'::jsonb,
    '["https://esignet-mock.collab.mosip.net"]'::jsonb,
    'CERTIFY_VC_SIGN_ED25519',
    'ED25519_SIGN',
    'Ed25519Signature2020',
    'EdDSA',
    'active',
    NOW()
) ON CONFLICT (issuer_id) DO NOTHING;

ALTER TABLE certify.credential_config
    ADD COLUMN IF NOT EXISTS issuer_id VARCHAR(64) NOT NULL DEFAULT 'default';

UPDATE certify.credential_config
SET issuer_id = 'default'
WHERE issuer_id IS NULL OR issuer_id = '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_credential_config_issuer'
    ) THEN
        ALTER TABLE certify.credential_config
            ADD CONSTRAINT fk_credential_config_issuer
            FOREIGN KEY (issuer_id) REFERENCES certify.issuer(issuer_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_credential_config_issuer_id ON certify.credential_config(issuer_id);
