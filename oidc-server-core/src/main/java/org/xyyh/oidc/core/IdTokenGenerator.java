package org.xyyh.oidc.core;

import com.nimbusds.jose.jwk.JWK;
import org.xyyh.oidc.userdetails.OidcUserDetails;

/**
 * id_token生成器，用于生成id_token
 */
public interface IdTokenGenerator {
    String generate(OidcUserDetails user, OAuth2ServerAccessToken accessToken, JWK jwk);
}
