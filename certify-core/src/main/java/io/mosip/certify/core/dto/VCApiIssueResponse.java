/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VCApiIssueResponse {

    /**
     * Signed credential:
     * <ul>
     *   <li>{@code ldp_vc} — JSON object (LDP verifiable credential with proof)</li>
     *   <li>{@code mso_mdoc} — base64url-encoded CBOR IssuerSigned mdoc string</li>
     * </ul>
     */
    private Object verifiableCredential;

    /**
     * Credential format that was issued ({@code ldp_vc} or {@code mso_mdoc}).
     */
    private String format;
}
