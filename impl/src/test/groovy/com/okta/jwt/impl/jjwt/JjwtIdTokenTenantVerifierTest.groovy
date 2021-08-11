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

import com.okta.commons.lang.Classes
import com.okta.jwt.Jwt
import com.okta.jwt.JwtVerificationException
import com.okta.jwt.impl.TestUtil
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SigningKeyResolver
import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.io.Serializer
import org.hamcrest.MatcherAssert
import org.testng.annotations.DataProvider
import org.testng.annotations.Test

import java.time.Duration
import java.time.Instant
import java.time.temporal.ChronoUnit

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.is

class JjwtIdTokenTenantVerifierTest extends TokenTenantVerifierTestSupport {

    final static String TEST_NONCE = "test-nonce"

    @Test(dataProvider = "invalidTenants")
    void invalidTenantsTest(Object tenant) {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("tn", tenant))
        }
    }

    @Test(dataProvider = "invalidNonce")
    void invalidNonceTest(Object nonce) {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("nonce", nonce))
        }
    }

    @Test
    void nullNonceTest() {
        invalidNonceTest(null)
    }

    @Test
    void noNonceExpected() {
        assertValidJwt(baseJwtBuilder()
                    .claim("nonce", null), this.signingKeyResolver, null)
    }

    @Override
    Jwt decodeToken(String tenant, String token, SigningKeyResolver signingKeyResolver) {
        return decodeToken(tenant, token, signingKeyResolver ?: this.signingKeyResolver, TEST_NONCE)
    }

    Jwt decodeToken(String tenant, String token, SigningKeyResolver signingKeyResolver, String nonce) {
        def verifier = new JjwtIdTokenTenantVerifier(TEST_ISSUER, Duration.ofSeconds(10L), signingKeyResolver)
        return verifier.decode(tenant, token, nonce)
    }

    @Override
    byte[] defaultFudgedBody() {
        Serializer serializer = Classes.loadFromService(Serializer)
        Instant now = Instant.now()
        def bodyMap = new DefaultClaims()
            .setIssuer(TEST_ISSUER)
            .setIssuedAt(Date.from(now))
            .setNotBefore(Date.from(now))
            .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
        bodyMap.put("nonce", TEST_NONCE)

        return serializer.serialize(bodyMap)
    }

    void assertValidJwt(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver = this.signingKeyResolver, String nonce = TEST_NONCE) {
        def result = buildThenDecodeToken(jwtBuilder, signingKeyResolver, nonce)
        assertThat result.getClaims().get("nonce"), is(nonce)
        assertThat result.getClaims().get("iss"), is(TEST_ISSUER)

        def tenant = result.getClaims().get("tn")
        if (tenant instanceof String) {
            MatcherAssert.assertThat(tenant, is("saasdev2"))
        }
    }

    Jwt buildThenDecodeToken(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver, String nonce) {

        def token = jwtBuilder
                .signWith(TEST_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)
                .compact()

        return decodeToken("saasdev2", token, signingKeyResolver, nonce)
    }

    @Override
    Jwt buildThenDecodeToken(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver) {
        return buildThenDecodeToken(jwtBuilder, signingKeyResolver ?: this.signingKeyResolver, TEST_NONCE)
    }

    @Override
    JwtBuilder baseJwtBuilder() {
        return super.baseJwtBuilder()
                .claim("nonce", TEST_NONCE)
    }

    @DataProvider(name = "invalidTenants")
    Object[][] invalidTenants() {
        return [
                [""],
                [" "],
                ["invalid-tenant"],
                [Collections.emptySet()],
                ["Test-Tenant"],
                [true],
        ]
    }


    @DataProvider(name = "invalidNonce")
    Object[][] invalidNonce() {
        return [
                [""],
                [" "],
                [".*"],
                ["some-invalid-nonce"],
                ["Test-Nonce"],
                [true]
        ]
    }
}
