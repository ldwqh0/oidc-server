package org.xyyh.oidc.provider;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.xyyh.oidc.core.IdTokenGenerator;
import org.xyyh.oidc.core.OAuth2ServerAccessToken;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.userdetails.OidcUserDetails;

import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.*;

/**
 * 默认的id_token构建器，用于构建id_token
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">https://openid.net/specs/openid-connect-core-1_0.html#IDToken</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#Claims">https://openid.net/specs/openid-connect-core-1_0.html#Claims</a>
 */
public class DefaultIdTokenGenerator implements IdTokenGenerator {
    private final Logger log = LoggerFactory.getLogger(DefaultIdTokenGenerator.class);

    @Override
    public String generate(String issuer, OidcUserDetails user, OAuth2ServerAccessToken accessToken, OidcAuthorizationRequest request, JWK jwk) throws JOSEException {
        Set<String> scope = accessToken.getScopes();
        Map<String, Object> claims = user.getClaims();
        Algorithm algorithm = jwk.getAlgorithm();
        if (Objects.isNull(algorithm) || !JWSAlgorithm.class.isAssignableFrom(algorithm.getClass())) {
            algorithm = JWSAlgorithm.RS256;
        }
        JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) algorithm).type(JOSEObjectType.JWT).build();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
            .issuer(issuer) // 发行人
            .subject(user.getSubject())
            .audience(request.getClientId()) // 接收人
            // 过期时间和access token时间一致
            .expirationTime(new Date(accessToken.getExpiresAt().toEpochMilli()))
            // 签发时间
            .issueTime(new Date(accessToken.getIssuedAt().toEpochMilli()))
            // 生效时间
            .notBeforeTime(new Date(accessToken.getIssuedAt().toEpochMilli()));
        // 暂时不包含jti
        // .jwtID("");  // id_token不包含jti
        claimsBuilder.claim("acr", "");
        String nonce = request.getAdditionalParameters().get(NONCE);
        if (StringUtils.isNotBlank(nonce)) {
            claimsBuilder.claim(NONCE, nonce);
        }
        if (scope.contains(OidcScopes.PROFILE)) {
            claimsBuilder.claim(NAME, user.getUsername())
                .claim(GIVEN_NAME, claims.get(GIVEN_NAME))
                .claim(FAMILY_NAME, claims.get(FAMILY_NAME))
                .claim(MIDDLE_NAME, claims.get(MIDDLE_NAME))
                .claim(NICKNAME, claims.get(NICKNAME))
                .claim(PREFERRED_USERNAME, claims.get(PREFERRED_USERNAME))
                .claim(PROFILE, claims.get(PROFILE))
                .claim(PICTURE, claims.get(PICTURE))
                .claim(WEBSITE, claims.get(WEBSITE))
                .claim(GENDER, claims.get(GENDER)) // female and male
                .claim(BIRTHDATE, claims.get(BIRTHDATE))
                .claim(ZONEINFO, claims.get(ZONEINFO))
                .claim(LOCALE, claims.get(LOCALE))
                .claim(UPDATED_AT, claims.get(UPDATED_AT));
        }
        if (scope.contains(OidcScopes.EMAIL)) {
            claimsBuilder.claim(EMAIL, claims.get(EMAIL))
                .claim(EMAIL_VERIFIED, claims.get(EMAIL_VERIFIED));
        }
        if (scope.contains(OidcScopes.ADDRESS)) {
            claimsBuilder.claim(ADDRESS, claims.get(ADDRESS));
        }
        if (scope.contains(OidcScopes.PHONE)) {
            claimsBuilder.claim(PHONE_NUMBER, claims.get(PHONE_NUMBER))
                .claim(PHONE_NUMBER_VERIFIED, claims.get(PHONE_NUMBER_VERIFIED));
        }
        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        try {
            JWSSigner signer = new RSASSASigner(jwk.toRSAKey());
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            log.error("sign jwt error", e);
            throw e;
        }
    }
}
