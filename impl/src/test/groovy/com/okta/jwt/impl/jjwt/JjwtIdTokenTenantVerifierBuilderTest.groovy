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
package com.okta.jwt.impl.jjwt

import com.okta.jwt.impl.TestUtil
import org.hamcrest.MatcherAssert
import org.testng.annotations.Test

import java.time.Duration

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.instanceOf
import static org.hamcrest.Matchers.is

class JjwtIdTokenTenantVerifierBuilderTest {

    @Test
    void orgIssuerTest() {
        def verifier = new JjwtIdTokenTenantVerifierBuilder()
                .setIssuer("https://issuer.example.com")
                .build()

        MatcherAssert.assertThat verifier.issuer, is("https://issuer.example.com")
        MatcherAssert.assertThat verifier.leeway, is(Duration.ofMinutes(2L))
        assertThat verifier.keyResolver, instanceOf(IssuerMatchingSigningKeyResolver)
        assertThat verifier.keyResolver.delegate, instanceOf(RemoteJwkSigningKeyResolver)
        MatcherAssert.assertThat verifier.keyResolver.delegate.jwkUri, is(new URL("https://issuer.example.com/oauth2/v1/keys"))
    }

    @Test
    void customIssuerTest() {
        def verifier = new JjwtIdTokenTenantVerifierBuilder()
                .setIssuer("https://issuer.example.com/oauth2/anAsId")
                .build()

        MatcherAssert.assertThat verifier.issuer, is("https://issuer.example.com/oauth2/anAsId")
        MatcherAssert.assertThat verifier.leeway, is(Duration.ofMinutes(2L))
        assertThat verifier.keyResolver, instanceOf(IssuerMatchingSigningKeyResolver)
        assertThat verifier.keyResolver.delegate, instanceOf(RemoteJwkSigningKeyResolver)
        MatcherAssert.assertThat verifier.keyResolver.delegate.jwkUri, is(new URL("https://issuer.example.com/oauth2/anAsId/v1/keys"))
    }

    @Test
    void issuer_nullTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtIdTokenTenantVerifierBuilder()
                    .setIssuer(null)
                    .build()
        }
    }

}
