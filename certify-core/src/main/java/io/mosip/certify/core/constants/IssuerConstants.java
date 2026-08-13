/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

public final class IssuerConstants {

    public static final String DEFAULT_ISSUER_ID = "default";
    public static final int ISSUER_ID_MAX_LENGTH = 64;
    public static final String ISSUER_ID_PATTERN =
            "^(?=.*[A-Za-z0-9])[A-Za-z0-9._:-]{1," + ISSUER_ID_MAX_LENGTH + "}$";
    public static final String KEY_APP_ID_PREFIX = "CERTIFY_ISSUER_";
    public static final String IACA_APP_ID_PREFIX = "CERTIFY_IACA_";
    public static final String DS_APP_ID_PREFIX = "CERTIFY_DS_";

    private IssuerConstants() {
    }
}
