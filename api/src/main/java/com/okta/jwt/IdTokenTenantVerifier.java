/*
 * Copyright 2018-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.jwt;


public interface IdTokenTenantVerifier {

    /**
     * Validates the given {@code idToken}.  Validates this token is valid Okta id token that has not expired.
     *
     *
     * @param tenant tenant name from header or path to validate
     * @param idToken string JWT id token to validate
     * @param nonce ID Token nonce - nullable
     * @return a decoded JWT
     * @throws JwtVerificationException when parsing or validation errors occur
     */
    Jwt decode(String tenant, String idToken, String nonce) throws JwtVerificationException;

    interface Builder extends VerifierBuilderSupport<Builder, IdTokenTenantVerifier> {
        Builder stub();
    }
}