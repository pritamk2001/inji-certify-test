# Current Architecture — Single Issuer per Instance

This document describes how Inji Certify handles **issuer identity** today. Understanding this is the foundation for multi-issuer work.

---

## Core mental model

Inji Certify separates two concepts that are often confused:

| Concept | What it is today | Where it lives |
|---------|------------------|----------------|
| **Credential Issuer** | The public identity of the issuer (URL in OID4VCI metadata) | Global property: `mosip.certify.domain.url` |
| **Credential Configuration** | Rules for issuing one type of VC (format, scope, signing keys) | Database table: `credential_config` |

**Key point:** A single Certify instance can have **many credential configurations** (Farmer VC, mDL, SD-JWT, etc.), but they all advertise the **same** `credential_issuer` URL.

There is **no `issuers` table** and **no issuer entity** in the codebase.

---

## Issuer identity layers

Certify uses issuer-related values at three layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: OID4VCI Metadata                                  │
│  credential_issuer = mosip.certify.domain.url               │
│  (one URL for the whole deployment)                         │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: DID Document                                      │
│  did-url = mosip.certify.data-provider-plugin.did-url       │
│  (one /.well-known/did.json for the whole deployment)       │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Per-VC Signing                                    │
│  didUrl = credential_config.did_url (per row)               │
│  (can differ per credential type; used at signing time)       │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration properties

All issuer-related settings are global Spring properties. There is no per-issuer configuration in the database.

| Property | Purpose | Used in |
|----------|---------|---------|
| `mosip.certify.domain.url` | OID4VCI `credential_issuer`; credential endpoint base URL | Metadata, credential endpoint |
| `mosip.certify.identifier` | VC `iss` claim (SD-JWT); proof validation; pre-auth offers | Signing, `JwtProofValidator`, `PreAuthorizedCodeService` |
| `mosip.certify.data-provider-plugin.did-url` | Global issuer DID | `/.well-known/did.json`, ledger, status-list VCs |
| `mosip.certify.authn.issuer-uri` | Expected access-token issuer (e-Signet) | `AccessTokenValidationFilter` |
| `mosip.certify.oauth.issuer` | OAuth AS metadata `issuer` field | `OAuthAuthorizationServerMetadataService`, IAR tokens |
| `mosip.certify.credential-config.issuer.display` | Localized display name/logo in metadata | `CredentialConfigurationServiceImpl` |
| `mosip.certify.credential-config.as-mapping` | Map credential-config IDs → authorization server URLs | Metadata `authorization_servers` |
| `mosip.certify.issuer.ledger-enabled` | Toggle ledger writes on issuance | `CertifyIssuanceServiceImpl` |
| `mosip.certify.discovery.issuer-id` | Defined in properties but **not used in Java code** | — (legacy / planned) |

Example from docker-compose reference config:

```properties
mosip.certify.domain.url=http://certify-nginx:80
mosip.certify.identifier=${mosip.certify.domain.url}
mosip.certify.data-provider-plugin.did-url=did:web:certify-nginx:80
mosip.certify.authn.issuer-uri=${mosip.certify.authorization.url}/v1/esignet
```

---

## How metadata is built

The well-known endpoint returns issuer metadata. The `credential_issuer` field is always the global `domain.url`:

```java
// CredentialConfigurationServiceImpl.java
@Value("${mosip.certify.domain.url}")
private String credentialIssuer;

private void populateCommonMetadataFields(CredentialIssuerMetadataDTO metadata, String version) {
    metadata.setCredentialIssuer(credentialIssuer);
    metadata.setAuthorizationServers(resolveAuthorizationServers());
    metadata.setCredentialEndpoint(buildCredentialEndpoint(version));
    metadata.setDisplay(issuerDisplay);
}
```

All **active** rows in `credential_config` are included in `credential_configurations_supported` — there is no filtering by issuer.

---

## Database schema (issuer-related)

There is no dedicated `issuers` table. Issuer-related columns exist on other tables:

### `credential_config.did_url`

Per-credential-type DID used for signing. Can differ from the global plugin DID.

```sql
-- certify-credential_config.sql
COMMENT ON COLUMN credential_config.did_url IS 'DID URL: Decentralized Identifier URL for the issuer.';
```

### `ledger.issuer_id`

Stores the issuer of the tracked credential. Today this is always the **global** `did-url`, not the per-config `didUrl`.

```sql
-- certify-ledger.sql
issuer_id VARCHAR(255) NOT NULL  -- Issuer of the TRACKED credential
```

### `ca_cert_store.issuer_id`

PKI CA chain storage for MOSIP Keymanager — **not** the OID4VCI credential issuer registry.

---

## Where issuer is used in code

| Area | Component | Issuer source |
|------|-----------|---------------|
| OID4VCI metadata | `CredentialConfigurationServiceImpl` | `mosip.certify.domain.url` |
| DID document | `CertifyIssuanceServiceImpl` → `DIDDocumentUtil` | Global `did-url` |
| VC signing (JSON-LD) | `Credential.addProof()` | Per-config `didUrl` |
| VC signing (SD-JWT) | Template params | `mosip.certify.identifier` |
| VC signing (mDoc) | `MDocCredential` | Per-config `didUrl` |
| Proof validation | `JwtProofValidator` | `mosip.certify.identifier` |
| Pre-auth offers | `PreAuthorizedCodeService` | `mosip.certify.identifier` |
| Ledger storage | `CertifyIssuanceServiceImpl` | Global `did-url` |
| Status list VCs | `StatusListCredentialService` | Global `did-url` |
| OAuth AS metadata | `OAuthAuthorizationServerMetadataService` | `mosip.certify.oauth.issuer` |
| Access token validation | `AccessTokenValidationFilter` | `mosip.certify.authn.issuer-uri` |

---

## API endpoints (issuer-related)

Base path: `/v1/certify` (from `server.servlet.path`)

| Method | Path | Issuer relevance |
|--------|------|------------------|
| GET | `/.well-known/openid-credential-issuer` | Returns single `credential_issuer` + all credential configs |
| GET | `/.well-known/did.json` | Single issuer DID document |
| GET | `/.well-known/jwks.json` | Issuer/OAuth JWKS |
| GET | `/.well-known/oauth-authorization-server` | OAuth AS `issuer` |
| POST | `/issuance/credential` | Issues VC with issuer signing |
| POST | `/credential-configurations` | CRUD; includes `didUrl` per config |
| POST | `/ledger-search`, `/v2/ledger-search` | Requires `issuerId` in request body |
| POST | `/pre-authorized-data` | Creates offer with `credential_issuer` |

None of these endpoints accept an issuer ID or path parameter today.

---

## What looks like multi-issuer (but is not)

### Wallet-side abstraction (Mimoto)

In the docker injistack, Mimoto lists `Farmer` and `MockMdl` as separate wallet issuers. Both point to the **same** Certify well-known URL:

```json
{
  "issuer_id": "Farmer",
  "wellknown_endpoint": "http://certify-nginx/.well-known/openid-credential-issuer"
}
```

```json
{
  "issuer_id": "MockMdl",
  "wellknown_endpoint": "http://certify-nginx/.well-known/openid-credential-issuer"
}
```

Differentiation is wallet-side (display, token proxy) and by scope/credential configuration — not separate Certify issuer endpoints.

### Partial multi-authorization-server support

`mosip.certify.credential-config.as-mapping` allows different authorization servers per credential configuration ID, while keeping one `credential_issuer`:

```properties
mosip.certify.credential-config.as-mapping={"FarmerLandRegistry":"https://esignet.example.com"}
```

### Per-config `didUrl`

Each `credential_config` row can have its own `didUrl` for signing. The DID document at `/.well-known/did.json` still uses the global `did-url` and aggregates keys from all active configs.

See [Credential Configuration](../Credential-Issuer-Configuration.md) for details on `didUrl` usage.

---

## Current scaling model

To run multiple logical issuers in production today, operators typically:

1. **Deploy separate Certify instances** — one per issuer, each with its own `domain.url` and properties.
2. **Use wallet-side abstraction** — Mimoto/Inji Web presents multiple issuers that all call the same Certify instance (limited; same metadata URL for all).

Neither approach gives true multi-issuer support inside a single Certify deployment.

---

## Next

- [Issuer Flow](./Issuer-Flow.md) — Step-by-step OID4VCI flow
- [Gap Analysis](./Gap-Analysis.md) — What needs to change
- [Implementation Plan](./Implementation-Plan.md) — How to build multi-issuer support
