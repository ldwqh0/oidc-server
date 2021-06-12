package org.xyyh.oidc.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.xyyh.oidc.core.OAuth2AuthorizationServerTokenService;
import org.xyyh.oidc.server.security.ServerOpaqueTokenAuthenticationManager;

import javax.servlet.http.HttpServletRequest;

@Order(98)
@EnableWebSecurity
public class ResourceServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final OAuth2AuthorizationServerTokenService tokenService;

    public ResourceServerSecurityConfiguration(OAuth2AuthorizationServerTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 禁用form登录
        http.formLogin().disable()
            // 禁止http basic 认证
            .httpBasic().disable()
            // 禁用csrf
            .csrf().disable()
            // 禁止session创建
            .anonymous().disable()
            .logout().disable()
            .authorizeRequests().anyRequest().fullyAuthenticated();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.oauth2ResourceServer()
            .bearerTokenResolver(bearerTokenResolver())
            .opaqueToken()
            .authenticationManager(new ServerOpaqueTokenAuthenticationManager(tokenService));
        http.requestMatcher(new BearerTokenRequestMatcher(bearerTokenResolver()));
    }

    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        return new DefaultBearerTokenResolver();
    }

    private final static class BearerTokenRequestMatcher implements RequestMatcher {

        private final BearerTokenResolver bearerTokenResolver;

        private BearerTokenRequestMatcher(BearerTokenResolver bearerTokenResolver) {
            this.bearerTokenResolver = bearerTokenResolver;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            try {
                return this.bearerTokenResolver.resolve(request) != null;
            } catch (OAuth2AuthenticationException ex) {
                return false;
            }
        }
    }

}
