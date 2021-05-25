package org.xyyh.oidc.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.xyyh.oidc.client.ClientDetailsService;
import org.xyyh.oidc.client.InMemoryClientDetailsService;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.*;
import org.xyyh.oidc.endpoint.converter.AccessTokenConverter;
import org.xyyh.oidc.endpoint.converter.DefaultAccessTokenConverter;
import org.xyyh.oidc.provider.*;

@Configuration
public class AuthorizationServerConfiguration {
    @Bean
    @ConditionalOnMissingBean({ClientDetailsService.class})
    public ClientDetailsService clientDetailsService() {
        return new InMemoryClientDetailsService();
    }

    @Bean
    public AuthorizationEndpoint authorizationEndpoint(ClientDetailsService clientDetailsService,
                                                       OAuth2AuthorizationRequestValidator oAuth2RequestValidator,
                                                       UserApprovalHandler userApprovalHandler,
                                                       OAuth2AuthorizationCodeStore authorizationCodeService,
                                                       OAuth2AuthorizationServerTokenService tokenServices,
                                                       AccessTokenConverter accessTokenConverter) {
        return new AuthorizationEndpoint(
            clientDetailsService,
            oAuth2RequestValidator,
            userApprovalHandler,
            authorizationCodeService
        );
    }

    @Bean
    public ServerDiscoveryEndpoint discoveryEndpoint(ObjectMapper objectMapper) {
        return new ServerDiscoveryEndpoint(objectMapper);
    }

    @Bean
    public TokenEndpoint tokenEndpoint(OAuth2AuthorizationCodeStore authorizationCodeService,
                                       PkceValidator pkceValidator,
                                       OAuth2AuthorizationServerTokenService tokenService,
                                       AccessTokenConverter accessTokenConverter,
                                       IdTokenGenerator idTokenGenerator) throws JOSEException {
        return new TokenEndpoint(
            authorizationCodeService,
            tokenService,
            accessTokenConverter,
            pkceValidator,
            idTokenGenerator,
            jwkSet()
        );
    }

    @Bean
    public JWKSetEndpoint keySetEndpoint() throws JOSEException {
        return new JWKSetEndpoint(jwkSet());
    }

    @Bean
    public TokenIntrospectionEndpoint tokenIntrospectionEndpoint(OAuth2TokenIntrospectionService tokenIntrospectionService) {
        return new TokenIntrospectionEndpoint(tokenIntrospectionService);
    }

    @Bean
    public UserInfoEndpoint userInfoEndpoint() {
        return new UserInfoEndpoint();
    }

    /**
     *
     */
    @Bean
    public JWKSet jwkSet() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID("default-sign")
            .keyUse(KeyUse.SIGNATURE)
            .generate();
        return new JWKSet(rsaKey);
    }

    /**
     * 保存Access Token
     */
    @Bean
    @ConditionalOnMissingBean(OAuth2AccessTokenStore.class)
    public OAuth2AccessTokenStore oAuth2AccessTokenService() {
        return new InMemoryAccessTokenStore();
    }

    /**
     * 保存 Authorization Code
     */
    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizationCodeStore.class)
    public OAuth2AuthorizationCodeStore oAuth2AuthorizationCodeService() {
        return new InMemoryAuthorizationCodeStore();
    }


    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizationRequestValidator.class)
    public OAuth2AuthorizationRequestValidator oAuth2RequestValidator() {
        return new DefaultOAuth2AuthorizationRequestValidator();
    }


    @Bean
    @ConditionalOnMissingBean(UserApprovalHandler.class)
    public UserApprovalHandler userApprovalHandler(ApprovalResultStore approvalStoreService) {
        return new ApprovalStoreUserApprovalHandler(approvalStoreService);
    }

    @Bean
    @ConditionalOnMissingBean(ApprovalResultStore.class)
    public ApprovalResultStore approvalStoreService() {
        return new InMemoryApprovalStore();
    }

    @Bean
    @ConditionalOnMissingBean(PkceValidator.class)
    public PkceValidator pkceValidator() {
        return new CompositePkceValidator(
            new PlainPkceValidator(),
            new S256PkceValidator()
        );
    }

    @Bean
    @ConditionalOnMissingBean({OAuth2AuthorizationServerTokenService.class, OAuth2ResourceServerTokenService.class})
    public DefaultTokenService tokenService(OAuth2AccessTokenStore tokenStorageService) {
        return new DefaultTokenService(tokenStorageService);
    }

    @Bean
    @ConditionalOnMissingBean(AccessTokenConverter.class)
    public AccessTokenConverter accessTokenConverter() {
        return new DefaultAccessTokenConverter();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2TokenIntrospectionService.class)
    public OAuth2TokenIntrospectionService tokenIntrospectionService(OAuth2AccessTokenStore tokenStore, AccessTokenConverter accessTokenConverter) {
        return new DefaultOAuth2TokenIntrospectionService(tokenStore, accessTokenConverter);
    }

    @Bean
    @ConditionalOnMissingBean(IdTokenGenerator.class)
    public IdTokenGenerator idTokenGenerator() {
        return new DefaultIdTokenGenerator();
    }
}
