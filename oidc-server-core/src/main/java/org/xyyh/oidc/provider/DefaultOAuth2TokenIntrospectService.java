package org.xyyh.oidc.provider;

import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.converter.AccessTokenConverter;

import java.util.Map;
import java.util.Optional;

public class DefaultOAuth2TokenIntrospectService implements OAuth2TokenIntrospectService {

    private final OAuth2AccessTokenStore tokenStore;

    private final AccessTokenConverter accessTokenConverter;

    public DefaultOAuth2TokenIntrospectService(OAuth2AccessTokenStore tokenStore, AccessTokenConverter accessTokenConverter) {
        this.tokenStore = tokenStore;
        this.accessTokenConverter = accessTokenConverter;
    }

    @Override
    public Optional<Map<String, Object>> introspectAccessToken(String accessToken) {
        return tokenStore.getAccessToken(accessToken)
            .flatMap(this::toAccessTokenIntrospectionResponse);
    }

    @Override
    public Optional<Map<String, Object>> introspectRefreshToken(String refreshToken) {
        return tokenStore.getRefreshToken(refreshToken)
            .flatMap(this::toRefreshTokenIntrospectionResponse);
    }

    private Optional<Map<String, Object>> toRefreshTokenIntrospectionResponse(OAuth2ServerRefreshToken refreshToken) {
        return tokenStore.loadAuthenticationByRefreshToken(refreshToken.getTokenValue())
            .map(authentication -> this.toRefreshTokenIntrospectionResponse(refreshToken, authentication));
    }

    private Optional<Map<String, Object>> toAccessTokenIntrospectionResponse(OAuth2ServerAccessToken accessToken) {
        return tokenStore.loadAuthentication(accessToken.getTokenValue())
            .map(authentication -> this.accessTokenConverter.toAccessTokenIntrospectionResponse(accessToken, authentication));
    }

    private Map<String, Object> toRefreshTokenIntrospectionResponse(OAuth2ServerRefreshToken refreshToken, OidcAuthentication authentication) {
        // TODO 构建refresh token 的检查响应
        return null;
    }
}
