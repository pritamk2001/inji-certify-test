-- Multi-issuer support: issuer registry and credential_config.issuer_id

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
    status                  VARCHAR(16)   NOT NULL DEFAULT 'ACTIVE',
    cr_dtimes               TIMESTAMP     NOT NULL DEFAULT NOW(),
    upd_dtimes              TIMESTAMP,
    CONSTRAINT pk_issuer_id PRIMARY KEY (issuer_id)
);

INSERT INTO certify.issuer (
    issuer_id, credential_issuer_url, did_url, identifier, display, status, cr_dtimes
) VALUES (
    'default',
    'http://localhost:8090',
    'did:web:localhost:8090',
    'http://localhost:8090',
    '[]'::jsonb,
    'active',
    NOW()
) ON CONFLICT (issuer_id) DO NOTHING;

ALTER TABLE certify.credential_config
    ADD COLUMN IF NOT EXISTS issuer_id VARCHAR(64) NOT NULL DEFAULT 'default';

UPDATE certify.credential_config SET issuer_id = 'default' WHERE issuer_id IS NULL;

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

-- Scope credential uniqueness per issuer (same type/context/vct/doctype allowed across issuers)
DROP INDEX IF EXISTS certify.idx_credential_config_type_context_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_sd_jwt_vct_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_doctype_unique;

CREATE UNIQUE INDEX idx_credential_config_type_context_unique
ON certify.credential_config(issuer_id, credential_type, context, credential_format)
WHERE credential_type IS NOT NULL AND credential_type <> ''
AND context IS NOT NULL AND context <> '';

CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
ON certify.credential_config(issuer_id, sd_jwt_vct, credential_format)
WHERE sd_jwt_vct IS NOT NULL AND sd_jwt_vct <> '';

CREATE UNIQUE INDEX idx_credential_config_doctype_unique
ON certify.credential_config(issuer_id, doctype, credential_format)
WHERE doctype IS NOT NULL AND doctype <> '';

ALTER TABLE certify.status_list_credential
    ADD COLUMN IF NOT EXISTS issuer_id VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_slc_issuer_id ON certify.status_list_credential(issuer_id);
