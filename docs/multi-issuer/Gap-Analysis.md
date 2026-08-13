# Gap Analysis — Multi-Issuer Support

This document lists what is **missing or inconsistent** in the current codebase for true multi-issuer support in a single Certify deployment.

---

## Definition: true multi-issuer

| Capability | Single issuer (today) | True multi-issuer (goal) |
|------------|----------------------|--------------------------|
| Issuer registry | Global Spring properties | Database-backed issuer entity |
| Well-known endpoints | One set for the deployment | One set **per issuer** |
| Metadata | All credential configs in one document | Only configs belonging to that issuer |
| `credential_issuer` URL | One URL | Unique URL per issuer |
| DID document | One `/.well-known/did.json` | Per-issuer DID document |
| Issuance endpoint | Shared; no issuer context | Scoped to issuer; cross-issuer isolation |
| Admin APIs | Credential-config CRUD only | Issuer CRUD + credential-config per issuer |

---

## Gap 1 — No issuer registry

**Today:**

- Issuer identity = `mosip.certify.domain.url`, `mosip.certify.identifier`, `mosip.certify.data-provider-plugin.did-url`
- No `issuers` table, no `Issuer` entity, no issuer admin API

**Impact:**

- Cannot onboard a new issuer without redeploying or changing global properties
- Cannot deactivate an issuer independently
- Cannot assign credential configurations to specific issuers

**Needed:**

- `issuer` table with lifecycle (ACTIVE / INACTIVE)
- `issuer_id` foreign key on `credential_config`
- Issuer CRUD APIs

---

## Gap 2 — Single well-known endpoints

**Today:**

```
GET /.well-known/openid-credential-issuer   → all configs, one credential_issuer
GET /.well-known/did.json                   → one DID doc
GET /.well-known/jwks.json                  → one JWKS
```

No path parameter, host routing, or issuer selector.

**Impact:**

- Wallets cannot discover issuer-specific metadata
- Two logical issuers (e.g. Agriculture Dept vs Transport Dept) cannot have separate `credential_issuer` URLs on the same instance

**Needed:**

```
GET /issuers/{issuerId}/.well-known/openid-credential-issuer
GET /issuers/{issuerId}/.well-known/did.json
GET /issuers/{issuerId}/.well-known/jwks.json
```

---

## Gap 3 — Metadata not filtered by issuer

**Today:**

`CredentialConfigurationServiceImpl` loads all active `credential_config` rows and sets one global `credential_issuer`.

**Impact:**

- Farmer and mDL configs appear together in the same metadata document
- No way to expose only one department's credentials to a wallet

**Needed:**

- Filter `credential_config` by `issuer_id`
- Set `credential_issuer` from issuer registry, not global property

---

## Gap 4 — Inconsistent issuer identity across formats

**Today:**

| Use case | Issuer source |
|----------|---------------|
| OID4VCI metadata | `domain.url` |
| JSON-LD signing | `credential_config.didUrl` |
| SD-JWT `iss` claim | `identifier` (global) |
| Proof `aud` validation | `identifier` (global) |
| Ledger `issuer_id` | Global `did-url` |
| Pre-auth `credential_issuer` | `identifier` (global) |
| Status list VC `issuer` | Global `did-url` |

**Impact:**

- Per-config `didUrl` can differ from global `identifier` and `did-url`
- SD-JWT credentials may have a different `iss` than the DID used for JSON-LD proofs
- Ledger search by `issuer_id` does not reflect per-config signing DIDs

**Needed:**

- Single source of truth per issuer: `credential_issuer_url`, `identifier`, `did_url`
- All signing, proof validation, ledger, and offers use the resolved issuer context

---

## Gap 5 — No issuer context at issuance

**Today:**

`POST /issuance/credential` has no issuer parameter. Any valid scope matching any active credential config can be issued.

**Impact:**

- No enforcement that a credential config belongs to a specific issuer
- Future multi-issuer routing cannot isolate issuance paths

**Needed:**

- Issuer resolution from URL path (or host)
- Scope must map to a credential config **owned by that issuer**
- Proof `aud` must match that issuer's `credential_issuer_url` / `identifier`

---

## Gap 6 — Wallet-side workaround is not real multi-issuer

**Today (injistack):**

Mimoto `mimoto-issuers-config.json` lists multiple issuers (`Farmer`, `MockMdl`) with different display and token endpoints, but the same:

```json
"wellknown_endpoint": "http://certify-nginx/.well-known/openid-credential-issuer"
```

**Impact:**

- Wallet UX shows multiple issuers; Certify exposes one
- OID4VCI spec expects `credential_issuer` to uniquely identify the issuer
- Verifiers may not distinguish issuers correctly

**Needed:**

- Per-issuer well-known URLs in wallet config
- Certify exposes distinct `credential_issuer` per issuer

---

## Gap 7 — Authorization server mapping is global

**Today:**

`mosip.certify.credential-config.as-mapping` is a global property mapping credential-config IDs to authorization server URLs.

**Impact:**

- Different issuers cannot have different default authorization servers without property file changes
- No per-issuer OAuth AS configuration

**Needed:**

- Per-issuer `authorization_servers` in issuer registry
- Optional per-issuer `authn.issuer-uri` for token validation

---

## Gap 8 — Key management not namespaced by issuer

**Today:**

Signing keys are referenced via `credential_config.keyManagerAppId` and `keyManagerRefId`. No issuer-level namespace.

**Impact:**

- Key onboarding is manual; no formal issuer → keys binding
- Risk of credential configs using keys from another issuer's namespace

**Needed:**

- Issuer onboarding flow for keymanager keys
- Validation that credential config keys belong to the issuer

---

## Gap 9 — No migration path documented

**Today:**

Existing deployments rely on global properties. Any multi-issuer change must not break them.

**Needed:**

- Default issuer seeded from current properties
- All existing `credential_config` rows linked to default issuer
- Global well-known endpoints kept during deprecation period

---

## Gap summary table

| # | Gap | Severity | Phase to address |
|---|-----|----------|------------------|
| 1 | No issuer registry | High | Phase 1 |
| 2 | Single well-known endpoints | High | Phase 2 |
| 3 | Metadata not filtered | High | Phase 2 |
| 4 | Inconsistent issuer identity | High | Phase 3 |
| 5 | No issuer context at issuance | High | Phase 3 |
| 6 | Wallet workaround only | Medium | Phase 7 |
| 7 | Global AS mapping | Medium | Phase 4 |
| 8 | Key management not namespaced | Medium | Phase 5 |
| 9 | No migration path | High | Phase 1, 9 |

---

## What already helps (reuse, don't rebuild)

| Existing feature | Multi-issuer reuse |
|------------------|-------------------|
| `credential_config` table | Add `issuer_id` FK; keep format/signing fields |
| Per-config `didUrl` | Align with issuer `did_url` as default |
| `as-mapping` | Model per-issuer in issuer registry |
| Ledger `issuer_id` column | Already suitable; populate from issuer context |
| `CredentialConfigurationService` | Extend to accept issuer filter |
| Docker injistack multi-profile | Reference for Farmer + mDL on one instance |

---

## Next

- [Implementation Plan](./Implementation-Plan.md) — Phased roadmap to close these gaps
