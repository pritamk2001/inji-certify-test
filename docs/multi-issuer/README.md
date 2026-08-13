# Multi-Issuer Support for Inji Certify

This documentation explains how issuer identity works in Inji Certify today, and outlines the plan to add **production-grade multi-issuer support** in a single Certify deployment.

---

## Who is this for?

| Audience | Start here |
|----------|------------|
| **Tech leads / Inji team (POC review)** | **[POC Proposal](./Multi-issuer-POC-Proposal.md)** |
| New developers onboarding to Certify | [Current Architecture](./Current-Architecture.md) |
| Architects / tech leads evaluating multi-issuer | [Gap Analysis](./Gap-Analysis.md) |
| Implementation team | [Implementation Design](./Multi-issuer-impl-plan.md) |
| Anyone tracing the end-to-end flow | [Issuer Flow](./Issuer-Flow.md) |

---

## Quick summary

**Today:** One Certify instance = one credential issuer. Issuer identity comes from global Spring properties (`mosip.certify.domain.url`, `mosip.certify.identifier`, etc.). Multiple credential types can be issued, but they all share the same `credential_issuer` URL in OID4VCI metadata.

**Goal:** One Certify instance = many credential issuers. Issuer identity, keys, and DID are onboarded via a new **Issuer Onboarding API** (not at Certify startup). Per issuer: onboard templates → issue VCs.

**Delivery:** Single PR. Issuance paths unchanged — `issuerId` in request body / query param.

---

## Documentation index

1. **[Current Architecture](./Current-Architecture.md)** — How issuer identity is defined and used across the codebase today.
2. **[Issuer Flow](./Issuer-Flow.md)** — End-to-end OID4VCI flow from wallet discovery to credential issuance.
3. **[Gap Analysis](./Gap-Analysis.md)** — What is missing for true multi-issuer support.
4. **[POC Proposal](./Multi-issuer-POC-Proposal.md)** — What was built in the POC, alignment with the design, gaps, and phasing for team / lead review.
5. **[Implementation Design](./Multi-issuer-impl-plan.md)** — Full technical design: Issuer Onboarding API, NEW vs CHANGED, file touch map, flows.

---

## Related existing docs

- [Credential Configuration](../Credential-Issuer-Configuration.md) — Managing credential types (formats, signing, `didUrl` per config).
- [VC Revocation Support](../VC-Revocation-Support.md) — Ledger and status list (uses `issuer_id`).
- [Pre-Authorized Code](../Pre-Authorized-Code.md) — Credential offers with `credential_issuer` field.
