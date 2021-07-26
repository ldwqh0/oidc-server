package org.xyyh.oidc.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.util.ResourceUtils;
import org.xyyh.oidc.client.ClientDetailsService;
import org.xyyh.oidc.client.InMemoryClientDetailsService;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.*;
import org.xyyh.oidc.endpoint.converter.AccessTokenConverter;
import org.xyyh.oidc.endpoint.converter.DefaultAccessTokenConverter;
import org.xyyh.oidc.provider.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static org.apache.commons.lang3.StringUtils.defaultIfBlank;
import static org.apache.commons.lang3.StringUtils.defaultIfEmpty;

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
                                                       OAuth2AuthorizationCodeStore authorizationCodeService) {
        return new AuthorizationEndpoint(
            clientDetailsService,
            oAuth2RequestValidator,
            userApprovalHandler,
            authorizationCodeService
        );
    }

    @Bean
    public ServerDiscoveryEndpoint discoveryEndpoint() {
        return new ServerDiscoveryEndpoint();
    }

    @Bean
    public TokenEndpoint tokenEndpoint(OAuth2AuthorizationCodeStore authorizationCodeService,
                                       PkceValidator pkceValidator,
                                       OAuth2AuthorizationServerTokenService tokenService,
                                       AccessTokenConverter accessTokenConverter,
                                       IdTokenGenerator idTokenGenerator,
                                       JWKSet jwkSet) {
        return new TokenEndpoint(
            authorizationCodeService,
            tokenService,
            accessTokenConverter,
            pkceValidator,
            idTokenGenerator,
            jwkSet
        );
    }

    @Bean
    public JWKSetEndpoint keySetEndpoint(JWKSet jwkSet) {
        return new JWKSetEndpoint(jwkSet);
    }

    @Bean
    public TokenIntrospectEndpoint tokenIntrospectionEndpoint(OAuth2TokenIntrospectService tokenIntrospectionService) {
        return new TokenIntrospectEndpoint(tokenIntrospectionService);
    }

    @Bean
    public UserInfoEndpoint userInfoEndpoint(OidcUserInfoService userClaimsService) {
        return new UserInfoEndpoint(userClaimsService);
    }

    @Bean
    @ConditionalOnMissingBean(OidcUserInfoService.class)
    public OidcUserInfoService userClaimsService() {
        return new UserdetailsToOidcUserInfoService();
    }


    @Bean
    @ConditionalOnMissingBean(JWKSet.class)
    @ConditionalOnProperty("xyyh.oidc.key-store")
    public JWKSet loadJwkSet(OidcServerProperties serverProperties) throws KeyStoreException, NoSuchProviderException, JOSEException, IOException, CertificateException, NoSuchAlgorithmException {
        String path = serverProperties.getKeyStore();
        String provider = serverProperties.getKeyStoreProvider();
        String type = defaultIfBlank(serverProperties.getKeyStoreType(), "JKS");
        char[] keyStorePasswordChars = defaultIfEmpty(serverProperties.getKeyStorePassword(), "").toCharArray();
        char[] keyPasswordChars = defaultIfEmpty(serverProperties.getKeyPassword(), "").toCharArray();
        // 初始化keystore
        KeyStore keyStore = StringUtils.isBlank(provider) ? KeyStore.getInstance(type) : KeyStore.getInstance(type, provider);
        URL url = ResourceUtils.getURL(path);
        try (InputStream stream = url.openStream()) {
            keyStore.load(stream, keyStorePasswordChars);
        }
        // 确定证书的别名
        String alias = StringUtils.getIfBlank(serverProperties.getKeyAlias(), () -> {
            try {
                return keyStore.aliases().nextElement();
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
        });
        RSAKey key = new RSAKey.Builder(RSAKey.load(keyStore, alias, keyPasswordChars)).keyUse(KeyUse.SIGNATURE).build();
        return new JWKSet(key);
    }

    /**
     *
     */
    @Bean
    @ConditionalOnMissingBean(JWKSet.class)
    public JWKSet jwkSet() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID("generated-sign")
            .keyUse(KeyUse.SIGNATURE)
            .generate();
        return new JWKSet(rsaKey);
    }

    @Bean
    @ConfigurationProperties(prefix = "xyyh.oidc")
    public OidcServerProperties keyStoreProperties() {
        return new OidcServerProperties();
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
    @ConditionalOnMissingBean({OAuth2AuthorizationServerTokenService.class})
    public DefaultTokenService tokenService(OAuth2AccessTokenStore tokenStorageService) {
        return new DefaultTokenService(tokenStorageService);
    }

    @Bean
    @ConditionalOnMissingBean(AccessTokenConverter.class)
    public AccessTokenConverter accessTokenConverter() {
        return new DefaultAccessTokenConverter();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2TokenIntrospectService.class)
    public OAuth2TokenIntrospectService tokenIntrospectionService(OAuth2AccessTokenStore tokenStore, AccessTokenConverter accessTokenConverter) {
        return new DefaultOAuth2TokenIntrospectService(tokenStore, accessTokenConverter);
    }

    @Bean
    @ConditionalOnMissingBean(IdTokenGenerator.class)
    public IdTokenGenerator idTokenGenerator(OidcUserInfoService userInfoService) {
        return new DefaultIdTokenGenerator(userInfoService);
    }

    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        return new DefaultBearerTokenResolver();
    }
}
