package org.xyyh.oidc.configuration;

import org.apache.commons.lang3.StringUtils;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.xyyh.oidc.client.ClientDetailsService;
import org.xyyh.oidc.server.security.web.authentication.www.PublicClientAuthenticationFilter;

import static org.xyyh.oidc.client.ClientDetails.ClientType.*;

@Order(99)
@EnableWebSecurity
public class AuthorizationServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final ClientDetailsService clientDetailsService;

    public AuthorizationServerSecurityConfiguration(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().antMatchers(
            "/oauth2/token",
            "/oauth2/certs",
            "/oauth2/token/introspection",
            "/oauth2/.well-known/openid-configuration");
        http.anonymous();
        // 根据rfc6749,如果客户端验证未通过，应用返回401和WWW-Authenticate header
        http.httpBasic().and()
            .formLogin().disable()
            .csrf().disable()
            .logout().disable();
        http.authorizeRequests()
            // 发现节点不做验证
            .antMatchers("/oauth2/certs", "/oauth2/.well-known/openid-configuration").permitAll()
            // 资源服务器可以访问token introspection节点
            .antMatchers("/oauth2/token/introspect").hasAnyAuthority("ROLE_" + CLIENT_RESOURCE)
            // client可以访问token节点
            .antMatchers("/oauth2/token").hasAnyAuthority("ROLE_" + CLIENT_PUBLIC, "ROLE_" + CLIENT_CONFIDENTIAL)
            .anyRequest().fullyAuthenticated();
        // 否则在同一浏览器环境下测试，会造成client的安全上下文和user的安全上下文混乱
        http.addFilterBefore(new PublicClientAuthenticationFilter(clientDetailsService), BasicAuthenticationFilter.class);
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(clientDetailsService::loadClientByClientId)
            .passwordEncoder(passwordEncoder());
    }

    private PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return StringUtils.equals(rawPassword, encodedPassword);
            }

            @Override
            public String encode(CharSequence encodedPassword) {
                return encodedPassword.toString();
            }
        };
    }

}
