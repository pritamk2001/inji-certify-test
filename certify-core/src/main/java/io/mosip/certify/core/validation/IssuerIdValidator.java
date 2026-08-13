/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.validation;

import io.mosip.certify.core.constants.IssuerConstants;

public final class IssuerIdValidator {

    public static final int MAX_LENGTH = IssuerConstants.ISSUER_ID_MAX_LENGTH;

    private IssuerIdValidator() {
    }

    public static String normalize(String issuerId) {
        if (issuerId == null) {
            return null;
        }
        String trimmed = issuerId.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public static boolean isValid(String issuerId) {
        String normalized = normalize(issuerId);
        return normalized != null && normalized.matches(IssuerConstants.ISSUER_ID_PATTERN);
    }
}
