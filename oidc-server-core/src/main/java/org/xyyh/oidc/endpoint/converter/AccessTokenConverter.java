package org.xyyh.oidc.endpoint.converter;

import org.xyyh.oidc.core.OidcAuthentication;
import org.xyyh.oidc.core.OAuth2ServerAccessToken;

import java.util.Map;

public interface AccessTokenConverter {

    Map<String, Object> toAccessTokenResponse(OAuth2ServerAccessToken token);

    Map<String, Object> toAccessTokenIntrospectionResponse(OAuth2ServerAccessToken token, OidcAuthentication authentication);
}
