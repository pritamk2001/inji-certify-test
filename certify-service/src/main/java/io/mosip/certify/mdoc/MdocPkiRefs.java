/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

/**
 * KeyManager application / reference ids for an issuer's mdoc IACA and Document Signer.
 */
public record MdocPkiRefs(
        String iacaAppId,
        String iacaRefId,
        String dsAppId,
        String dsRefId
) {
}
