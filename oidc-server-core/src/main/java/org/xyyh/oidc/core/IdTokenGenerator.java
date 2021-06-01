package org.xyyh.oidc.core;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.security.core.userdetails.UserDetails;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

/**
 * id_token生成器，用于生成id_token
 */
public interface IdTokenGenerator {
    String generate(String issuer, UserDetails user, OAuth2ServerAccessToken accessToken, OidcAuthorizationRequest request, JWK jwk) throws JOSEException;
}
