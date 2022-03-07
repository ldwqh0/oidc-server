package org.xzcode.oidc.provider;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.xzcode.oidc.core.OAuth2AccessTokenStore;
import org.xzcode.oidc.core.OAuth2ServerAccessToken;
import org.xzcode.oidc.core.OAuth2ServerRefreshToken;
import org.xzcode.oidc.core.OidcAuthentication;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 在内存中保存access token,如果使用该种形式保存，access token value和access token id是一致的
 */
public class InMemoryAccessTokenStore implements OAuth2AccessTokenStore {

    /**
     * the key is access token id ,the value is OidcAuthentication
     */
    private final Map<String, OidcAuthentication> tokenKeyAuthenticationRepository = new ConcurrentHashMap<>();

    /**
     * the key is token id,the value is OAuth2AccessToken
     */
    private final Map<String, OAuth2ServerAccessToken> tokenKey2AccessTokenRepository = new ConcurrentHashMap<>();

    /**
     * the key is refresh token ,the value is access token
     */
    private final Map<String, String> refreshToken2AccessTokenRepository = new ConcurrentHashMap<>();

    @Override
    public void delete(String token) {
        OAuth2ServerAccessToken accessToken = this.tokenKey2AccessTokenRepository.remove(token);
        Optional.ofNullable(accessToken)
            .flatMap(OAuth2ServerAccessToken::getRefreshToken)
            .map(OAuth2ServerRefreshToken::getTokenValue)
            .ifPresent(refreshToken2AccessTokenRepository::remove);
    }

    @Override
    public OAuth2ServerAccessToken save(OAuth2ServerAccessToken accessToken, OidcAuthentication authentication) {
        String tokenKey = accessToken.getId();
        this.tokenKeyAuthenticationRepository.put(tokenKey, authentication);
        this.tokenKey2AccessTokenRepository.put(tokenKey, accessToken);
        accessToken.getRefreshToken()
            .map(OAuth2ServerRefreshToken::getTokenValue)
            .ifPresent(refreshToken -> this.refreshToken2AccessTokenRepository.put(refreshToken, tokenKey));
        return accessToken;
    }

    @Override
    public Optional<OidcAuthentication> loadAuthentication(String accessToken) {
        return Optional.ofNullable(accessToken)
            .map(this.tokenKey2AccessTokenRepository::get)
            .filter(this::preCheckAccessToken)
            .map(OAuth2ServerAccessToken::getTokenValue)
            .map(this.tokenKeyAuthenticationRepository::get);
    }

    @Override
    public Optional<OAuth2ServerAccessToken> getAccessToken(String accessToken) {
        return Optional.ofNullable(accessToken)
            .map(this.tokenKey2AccessTokenRepository::get)
            .filter(this::preCheckAccessToken);
    }

    @Override
    public Optional<OAuth2ServerRefreshToken> getRefreshToken(String refreshToken) {
        return Optional.ofNullable(refreshToken)
            .map(refreshToken2AccessTokenRepository::get)
            .map(tokenKey2AccessTokenRepository::get)
            .flatMap(OAuth2ServerAccessToken::getRefreshToken)
            .filter(this::preCheckRefreshToken);
    }

    @Override
    public Optional<OAuth2ServerAccessToken> getAccessToken(final OidcAuthentication authentication) {
        return this.tokenKeyAuthenticationRepository
            .entrySet()
            .stream()
            .filter(it -> Objects.equals(extractAuthenticationKey(it.getValue()), extractAuthenticationKey(authentication)))
            .map(Map.Entry::getKey)
            .map(tokenKey2AccessTokenRepository::get)
            .findFirst()
            .filter(this::preCheckAccessToken);
    }

    @Override
    public Optional<OidcAuthentication> loadAuthenticationByRefreshToken(String refreshToken) {
        return Optional.ofNullable(refreshToken)
            .map(this.refreshToken2AccessTokenRepository::get) // 获取access token value
            .map(this.tokenKey2AccessTokenRepository::get) // 获取access token
            .flatMap(accessToken -> accessToken.getRefreshToken()
                // 找到并校验RefreshToken
                .filter(this::preCheckRefreshToken)
                // 如果refresh token存在并且没有过期，使用该refresh token对应的access token获取对应的access token
                .map(rt -> this.tokenKeyAuthenticationRepository.get(accessToken.getId()))
            );
    }

    @Override
    public Collection<OAuth2ServerAccessToken> findAccessTokenByUserPrincipal(Object principal) {
        return findTokenValueByUserPrincipal(principal)
            .map(tokenKey2AccessTokenRepository::get)
            .collect(Collectors.toList());
    }

    @Override
    public void deleteByRefreshToken(String refreshToken) {
        String accessTokenValue = refreshToken2AccessTokenRepository.get(refreshToken);
        delete(accessTokenValue);
    }

    private String extractAuthenticationKey(OidcAuthentication authentication) {
        String clientId = authentication.getClient().getClientId();
        List<String> scopes = new ArrayList<>(authentication.getScopes());
        Collections.sort(scopes);
        String name = authentication.getName();
        return DigestUtils.md5Hex(StringUtils.join("client:", clientId, "scopes:", StringUtils.join(scopes, ","), "name:", name));
    }

    private boolean preCheckAccessToken(OAuth2ServerAccessToken accessToken) {
        if (Instant.now().isAfter(accessToken.getExpiresAt())) {
            this.delete(accessToken.getId());
            return false;
        }
        return true;
    }

    private boolean preCheckRefreshToken(OAuth2ServerRefreshToken refreshToken) {
        if (Instant.now().isAfter(refreshToken.getExpiresAt())) {
            this.deleteByRefreshToken(refreshToken.getTokenValue());
            return false;
        }
        return true;
    }

    private Stream<String> findTokenValueByUserPrincipal(Object principal) {
        return this.tokenKeyAuthenticationRepository.entrySet()
            .stream()
            .filter(it -> Objects.equals(Objects.requireNonNull(it.getValue().getUser()).getPrincipal(), principal))
            .map(Map.Entry::getKey);
    }
}
