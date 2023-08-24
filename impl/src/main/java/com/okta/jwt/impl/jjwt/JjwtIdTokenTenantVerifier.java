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
package com.okta.jwt.impl.jjwt;

import com.okta.jwt.IdTokenTenantVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.lang.Objects;

import java.time.Duration;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public class JjwtIdTokenTenantVerifier extends TokenVerifierSupport implements IdTokenTenantVerifier {

    public JjwtIdTokenTenantVerifier(String issuer,
                                     Duration leeway,
                                     SigningKeyResolver signingKeyResolver) {

        super(issuer, leeway, signingKeyResolver);
    }

    @Override
    public Jwt decode(String tenant, String idToken, String nonce) throws JwtVerificationException {
       return decode(idToken, parser(), ClaimsValidator.compositeClaimsValidator(
               new ClaimsValidator.ContainsTenantClaimsValidator(tenant),
               jws -> {
                   String actualNonce = jws.getBody().get("nonce", String.class);
                   if (!Objects.nullSafeEquals(actualNonce, nonce)) {
                       throw new IncorrectClaimException(jws.getHeader(), jws.getBody(), "Claim `nonce` does not match expected value. Note: a `null` nonce is only valid when both the expected and actual values are `null`.");
                   }
               }));
    }
}