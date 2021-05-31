package org.xyyh.oidc.core;

import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.exception.RefreshTokenValidationException;
import org.xyyh.oidc.exception.TokenRequestValidationException;

import java.util.Collection;
import java.util.Optional;

public interface OAuth2AuthorizationServerTokenService {

    // 根据access
    Optional<OidcAuthentication> loadAuthentication(String accessToken);

    Optional<OAuth2ServerAccessToken> readAccessToken(String accessToken);

    /**
     * 创建一个新的Access token
     *
     * @param authentication oidc授权信息
     * @return 创建好的 access token对象
     */
    OAuth2ServerAccessToken createAccessToken(OidcAuthentication authentication);

    /**
     * 使用refresh token重新创建一个access token
     *
     * @param refreshToken //     * @param authentication
     * @return
     */
    OAuth2ServerAccessToken refreshAccessToken(String refreshToken, ClientDetails client, Collection<String> requestScopes) throws RefreshTokenValidationException, TokenRequestValidationException;
}
