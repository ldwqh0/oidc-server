package org.xyyh.oidc.provider;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.xyyh.oidc.core.IdTokenGenerator;
import org.xyyh.oidc.core.OAuth2ServerAccessToken;
import org.xyyh.oidc.core.OidcUserInfoService;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

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

    private final OidcUserInfoService userInfoService;

    public DefaultIdTokenGenerator(OidcUserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }

    @Override
    public String generate(String issuer, UserDetails user, OAuth2ServerAccessToken accessToken, OidcAuthorizationRequest request, JWK jwk) throws JOSEException {
        Set<String> scope = accessToken.getScopes();
        Map<String, Object> claims = userInfoService.loadOidcUserInfo(user).getClaims();
        Algorithm algorithm = jwk.getAlgorithm();
        if (Objects.isNull(algorithm) || !JWSAlgorithm.class.isAssignableFrom(algorithm.getClass())) {
            algorithm = JWSAlgorithm.RS256;
        }
        JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) algorithm).type(JOSEObjectType.JWT).build();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
            .issuer(issuer) // 发行人
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
        String nonce = request.getParameters().get(NONCE);
        if (StringUtils.isNotBlank(nonce)) {
            claimsBuilder.claim(NONCE, nonce);
        }
        copyClaims(claimsBuilder, claims, SUB);
        if (scope.contains(OidcScopes.PROFILE)) {
            copyClaims(claimsBuilder, claims,
                NAME, GIVEN_NAME, GIVEN_NAME, FAMILY_NAME, MIDDLE_NAME, NICKNAME, PREFERRED_USERNAME,
                PROFILE, PICTURE, WEBSITE, GENDER, BIRTHDATE,
                ZONEINFO, LOCALE, UPDATED_AT
            );
        }
        if (scope.contains(OidcScopes.EMAIL)) {
            copyClaims(claimsBuilder, claims, EMAIL, EMAIL_VERIFIED);
        }
        if (scope.contains(OidcScopes.ADDRESS)) {
            copyClaims(claimsBuilder, claims, ADDRESS);
        }
        if (scope.contains(OidcScopes.PHONE)) {
            copyClaims(claimsBuilder, claims, PHONE_NUMBER, PHONE_NUMBER_VERIFIED);
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

    private void copyClaims(JWTClaimsSet.Builder builder, Map<String, Object> source, String... keys) {
        for (String key : keys) {
            Object value = source.get(key);
            if (ObjectUtils.isNotEmpty(value)) {
                builder.claim(key, value);
            }
        }
    }
}
