package org.xyyh.oidc.core;

import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.exception.RefreshTokenValidationException;
import org.xyyh.oidc.exception.TokenRequestValidationException;

import java.util.Collection;

public interface OAuth2AuthorizationServerTokenService {

    OAuth2ServerAccessToken createAccessToken(OidcAuthentication authentication);

    /**
     * 使用refresh token重新创建一个access token
     *
     * @param refreshToken //     * @param authentication
     * @return
     */
    OAuth2ServerAccessToken refreshAccessToken(String refreshToken, ClientDetails client, Collection<String> requestScopes) throws RefreshTokenValidationException, TokenRequestValidationException;
}
