package org.xyyh.oidc.provider;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.collect.CollectionUtils;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.exception.RefreshTokenValidationException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.xyyh.oidc.collect.Sets.hashSet;

public class DefaultTokenService implements OAuth2AuthorizationServerTokenService {

    private Integer defaultAccessTokenValiditySeconds = 3600;
    private Integer defaultRefreshTokenValiditySeconds = 7200;

    private final OAuth2AccessTokenStore accessTokenStore;

    private final StringKeyGenerator stringGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder(), 33);

    /**
     * 对用户进行无密码的校验<br>
     * 用于refresh token校验
     */
    private ProviderManager preProviderManager;

    @Autowired(required = false)
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        if (userDetailsService != null) {
            this.preProviderManager = new ProviderManager(Collections.singletonList(new PreAuthenticatedProvider(userDetailsService)));
        }
    }

    public DefaultTokenService(OAuth2AccessTokenStore accessTokenStore) {
        this.accessTokenStore = accessTokenStore;
    }

    public void deleteAccessToken(String accessToken) {
        accessTokenStore.delete(accessToken);
    }

    @Override
    public OAuth2ServerAccessToken createAccessToken(final OidcAuthentication authentication) {
        OAuth2ServerAccessToken accessToken = accessTokenStore.getAccessToken(authentication)
                .map(existingAccessToken -> {
                    if (Instant.now().isAfter(existingAccessToken.getExpiresAt())) {
                        accessTokenStore.delete(existingAccessToken.getTokenValue());
                        return generateAccessToken(authentication.getClient(), authentication.getScopes());
                    } else {
                        return existingAccessToken;
                    }
                }).orElseGet(() -> generateAccessToken(authentication.getClient(), authentication.getScopes()));
        return accessTokenStore.save(accessToken, authentication);
    }

    @Override
    public OAuth2ServerAccessToken refreshAccessToken(String refreshToken, ClientDetails client, Collection<String> requestScopes) throws RefreshTokenValidationException {
        final String internRefreshTokenValue = refreshToken.intern();
        // 对token进行预检，如果检测失败，抛出异常
        loadAuthenticationByRefreshToken(refreshToken).orElseThrow(RefreshTokenValidationException::new);
        // 同一时刻，针对用一个refresh token,有且仅有一个线程可以读取某个refresh token的相关信息
        synchronized (internRefreshTokenValue) {
            // 进行双重检查
            OidcAuthentication preAuthentication = loadAuthenticationByRefreshToken(refreshToken).orElseThrow(RefreshTokenValidationException::new);
            // 验证传入的refresh token是否发布给该client
            if (!Objects.equals(preAuthentication.getClient().getClientId(), client.getClientId())) {
                throw new RefreshTokenValidationException("client validate failure");
            }
            // 验证重新请求的scope不能不能大于之前的scope
            Set<String> scopeToUse = preAuthentication.getScopes();
            if (!CollectionUtils.containsAll(preAuthentication.getScopes(), requestScopes)) {
                throw new RefreshTokenValidationException("scope validate failure");
            }
            if (CollectionUtils.isNotEmpty(requestScopes)) {
                scopeToUse = hashSet(requestScopes);
            }
            // 使用refreshToken时,需要重新加载用户的信息
            PreAuthenticatedAuthenticationToken preToken = new PreAuthenticatedAuthenticationToken(preAuthentication, preAuthentication.getAuthorities());
            // TODO details 需要处理,暂时没有向Authentication中setDetails 根据规则，应该设置一些来自请求的信息，比如请求ip啥的，参考spring的登录请求
            Authentication user = preProviderManager.authenticate(preToken);
            // 创建一个新的OAuth2Authentication
            OidcAuthentication authentication = OidcAuthentication.of(preAuthentication.getRequest(), ApprovalResult.of(scopeToUse), client, user);
            // 删除之前的access token
            accessTokenStore.deleteByRefreshToken(internRefreshTokenValue);
            // 创建一个新的token
            OAuth2ServerAccessToken accessToken = generateAccessToken(client, authentication.getScopes());

            return accessTokenStore.save(accessToken, authentication);
        }
    }

    @Override
    public void revokeAccessToken(String token) {
        if (StringUtils.isNotEmpty(token)) {
            accessTokenStore.delete(token);
        }
    }

    @Override
    public Optional<OidcAuthentication> loadAuthentication(String accessToken) {
        return accessTokenStore
                .getAccessToken(accessToken)
                .map(OAuth2ServerToken::getTokenValue)
                .flatMap(accessTokenStore::loadAuthentication);
    }


    @Override
    public Optional<OAuth2ServerAccessToken> readAccessToken(String accessToken) {
        return accessTokenStore.getAccessToken(accessToken);
    }

    public Optional<OidcAuthentication> loadAuthenticationByRefreshToken(String refreshToken) {
        return accessTokenStore
                .getRefreshToken(refreshToken)
                .map(OAuth2ServerRefreshToken::getTokenValue)
                .flatMap(accessTokenStore::loadAuthenticationByRefreshToken);
    }

    /**
     * 验证请求是否支持refresh_token
     *
     * @param client 待验证的client
     * @return 支持返回true, 不支持返回false
     */
    private boolean isSupportRefreshToken(ClientDetails client) {
        return this.preProviderManager != null && client.getAuthorizedGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN);
    }

    private OAuth2ServerAccessToken generateAccessToken(ClientDetails client, Set<String> scopes) {
        Instant issuedAt = Instant.now();
        Integer accessTokenValiditySeconds = Optional.ofNullable(client.getAccessTokenValiditySeconds()).orElse(defaultAccessTokenValiditySeconds);
        Instant expiresAt = issuedAt.plus(accessTokenValiditySeconds, ChronoUnit.SECONDS);
        String tokenId = stringGenerator.generateKey();
        OAuth2ServerRefreshToken refreshToken = null;
        if (isSupportRefreshToken(client)) {
            refreshToken = generateRefreshToken(client);
        }
        return OAuth2ServerAccessToken.of(tokenId, OAuth2AccessToken.TokenType.BEARER, tokenId, issuedAt, expiresAt, scopes, refreshToken);
    }

    private OAuth2ServerRefreshToken generateRefreshToken(ClientDetails client) {
        Instant issuedAt = Instant.now();
        Integer validitySeconds = Optional.ofNullable(client.getRefreshTokenValiditySeconds()).orElse(defaultRefreshTokenValiditySeconds);
        Instant expiresAt = issuedAt.plus(validitySeconds, ChronoUnit.SECONDS);
        String tokenValue = stringGenerator.generateKey();
        return OAuth2ServerRefreshToken.of(tokenValue, issuedAt, expiresAt);
    }

}
