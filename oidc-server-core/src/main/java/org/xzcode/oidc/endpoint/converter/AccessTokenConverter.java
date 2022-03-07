package org.xzcode.oidc.endpoint.converter;

import org.xzcode.oidc.core.OidcAuthentication;
import org.xzcode.oidc.core.OAuth2ServerAccessToken;

import java.util.Map;

public interface AccessTokenConverter {

    Map<String, Object> toAccessTokenResponse(OAuth2ServerAccessToken token);

    Map<String, Object> toAccessTokenIntrospectionResponse(OAuth2ServerAccessToken token, OidcAuthentication authentication);
}
