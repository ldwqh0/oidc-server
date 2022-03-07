package org.xzcode.oidc.core;

import org.springframework.transaction.annotation.Transactional;
import org.xzcode.oidc.client.ClientDetails;
import org.xzcode.oidc.exception.RefreshTokenValidationException;
import org.xzcode.oidc.exception.TokenRequestValidationException;

import java.util.Collection;
import java.util.Optional;

public interface OAuth2AuthorizationServerTokenService {

    /**
     * 根据accessToken 获取{@link OidcAuthentication}
     */
    Optional<OidcAuthentication> loadAuthentication(String accessToken);

    /**
     * 根据refreshToken获取 {@link OidcAuthentication}
     *
     * @param refreshToken refreshToken
     */
    Optional<OidcAuthentication> loadAuthenticationByRefreshToken(String refreshToken);

    /**
     * 根据 accessToken 获取{@link OAuth2ServerAccessToken}
     *
     * @param accessToken accessToken
     */
    Optional<OAuth2ServerAccessToken> readAccessToken(String accessToken);

    /**
     * 创建一个新的Access token
     *
     * @param authentication oidc授权信息
     * @return 创建好的 access token对象
     */
    @Transactional
    OAuth2ServerAccessToken createAccessToken(OidcAuthentication authentication);

    /**
     * 使用refresh token重新创建一个access token
     *
     * @param refreshToken //     * @param authentication
     */
    @Transactional
    OAuth2ServerAccessToken refreshAccessToken(String refreshToken, ClientDetails client, Collection<String> requestScopes) throws RefreshTokenValidationException, TokenRequestValidationException;

    /**
     * 使一个access token失效
     *
     * @param token 要删除的accessToken
     */
    @Transactional
    void revokeAccessToken(String token);

}
