ALTER TABLE certify.credential_config DROP CONSTRAINT IF EXISTS fk_credential_config_issuer;
DROP INDEX IF EXISTS certify.idx_credential_config_issuer_id;

-- Restore pre-multi-issuer global uniqueness (fails if cross-issuer duplicate type/context rows exist)
DROP INDEX IF EXISTS certify.idx_credential_config_type_context_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_sd_jwt_vct_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_doctype_unique;

CREATE UNIQUE INDEX idx_credential_config_type_context_unique
ON certify.credential_config(credential_type, context, credential_format)
WHERE credential_type IS NOT NULL AND credential_type <> ''
AND context IS NOT NULL AND context <> '';

CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
ON certify.credential_config(sd_jwt_vct, credential_format)
WHERE sd_jwt_vct IS NOT NULL AND sd_jwt_vct <> '';

CREATE UNIQUE INDEX idx_credential_config_doctype_unique
ON certify.credential_config(doctype, credential_format)
WHERE doctype IS NOT NULL AND doctype <> '';

ALTER TABLE certify.credential_config DROP COLUMN IF EXISTS issuer_id;

DROP INDEX IF EXISTS certify.idx_slc_issuer_id;
ALTER TABLE certify.status_list_credential DROP COLUMN IF EXISTS issuer_id;

DROP TABLE IF EXISTS certify.issuer;
