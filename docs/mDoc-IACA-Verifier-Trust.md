# mDoc IACA trust for verifiers (ISO/IEC 18013-5)

How verifiers trust Certify-issued `mso_mdoc` credentials, and how the Issuing Authority Certificate Authority (**IACA**) must be distributed.

---

## 1. ISO trust model (what a verifier expects)

Per **ISO/IEC 18013-5**:

| Location | Content |
|----------|---------|
| **Inside the mdoc** (`issuerAuth` COSE unprotected header) | Document Signer (**DS**) certificate only in `x5chain` (single cert) |
| **On the verifier / reader** (out of band) | Trusted **IACA** root certificate(s) in the reader trust store |

The verifier does **not** learn to trust IACA from the credential alone. IACA is disseminated separately (domestic channel or Master List).

```text
Reader trust store                    Presented mdoc
─────────────────                     ──────────────
[ IACA root ]  ──validate──►  x5chain[0] = DS cert
                                     │
                                     └── DS public key verifies COSE_Sign1 (MSO)
```

Rough verification steps (ISO):

1. Read DS from `issuerAuth` unprotected `x5chain`
2. Build path to a **known trusted IACA** already on the reader
3. Check profile / dates / countryName / DS Extended Key Usage (when certs are Annex B–conformant)
4. Verify COSE_Sign1 over the MSO with the DS public key
5. Re-hash disclosed items and match MSO `valueDigests`

If the reader does not have your IACA installed, verification fails even when the signature is valid.

---

## 2. What Certify issues today

- On issuer onboarding / bootstrap, Certify provisions **IACA + DS** in KeyManager and stores refs on the `issuer` row (`mdocIacaAppId`, `mdocDsAppId`, …).
- Each issued mdoc embeds the **DS** certificate in COSE `x5chain` (ISO-aligned shape: single cert).
- **IACA is not embedded** in the mdoc (matches ISO NOTE that issuerAuth `x5chain` is a single DS certificate).

Production signing uses **KeyManager DS only** (`mosip.certify.mdoc.allow-property-ds=false`). See [VC-API-mDoc-Support.md](./VC-API-mDoc-Support.md).

---

## 3. How to obtain the IACA from Certify (send to verifiers)

### Preferred: export API

```http
GET /v1/certify/issuers/{issuerId}/mdoc/iaca-certificate
```

Response:

```json
{
  "keyId": "CERTIFY_IACA_<ISSUER>",
  "certificateData": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

Save `certificateData` to a `.pem` file and distribute that file to verifier operators.

### Alternative: system-info + issuer metadata

1. `GET /v1/certify/issuers/{issuerId}` → note `mdocIacaAppId` / `mdocIacaRefId`
2. `GET /v1/certify/system-info/certificate?applicationId={mdocIacaAppId}&referenceId={mdocIacaRefId}`

---

## 4. How to send IACA to verifiers (operations)

ISO expects **secured, well-known channels**. Practical options:

| Channel | When to use |
|---------|-------------|
| **Partner pack** | Email / secure portal: PEM + issuer id + effective dates + contact |
| **TLS-protected publication** | Publish IACA PEM on the Issuing Authority website (document the URL) |
| **Onboarding checklist** | Require verifier ops to install PEM before going live |
| **Master List** (later / cross-border) | Aggregate IACAs for many issuers; readers import the list |

**Do not** rely on “trust whatever DS appears in the mdoc” without an IACA trust anchor.

Recommended steps for each verifier integration:

1. Export IACA PEM via `GET .../mdoc/iaca-certificate`
2. Transmit over an authenticated channel (or protected download)
3. Install into the **mDL reader / verifier trust store** as a CA / trust anchor
4. Smoke-test: present one Certify-issued mdoc; reader must validate DS → IACA → MSO signature
5. On **IACA re-key**, distribute the new IACA (and any ISO link certificate) and update stores

---

## 5. Device key / holder binding note

MSO `deviceKeyInfo` comes from `credentialSubject.id` (`did:jwk:...`) on the VC API. That path is **caller-trusted** today (API key). Cryptographic holder PoP is a separate follow-up; W3C `ldp_vc` issuance does not require this binding.

---

## 6. Production checklist (trust)

- [ ] Issuer onboarded with KeyManager `mdoc_iaca_*` / `mdoc_ds_*`
- [ ] `mosip.certify.mdoc.allow-property-ds=false` in production
- [ ] IACA PEM exported and given to every verifier
- [ ] Verifier trust store updated; successful external read of one issued mdoc
- [ ] Process documented for IACA renewal / revocation communications
