/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Document Signer private key and X.509 certificate used for local mDoc COSE signing.
 */
public record MdocDsKeyMaterial(PrivateKey privateKey, X509Certificate certificate) {
}
