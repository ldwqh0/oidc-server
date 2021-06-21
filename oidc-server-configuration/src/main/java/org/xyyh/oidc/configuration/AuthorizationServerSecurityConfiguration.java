package org.xyyh.oidc.configuration;

import org.apache.commons.lang3.StringUtils;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.xyyh.oidc.client.ClientDetailsService;

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
        http.authorizeRequests()
            .antMatchers("/oauth2/certs",
                "/oauth2/.well-known/openid-configuration")
            .permitAll()
            .anyRequest().fullyAuthenticated();
        // 根据rfc6749,如果客户端验证未通过，应用返回401和WWW-Authenticate header
        http.formLogin().disable().httpBasic();
        // 使用NullSecurityContextRepository,防止将相关的安全信息写入Session或者其它地方
        // 否则在同一浏览器环境下测试，会造成client的安全上下文和user的安全上下文混乱
        http.securityContext().securityContextRepository(new NullSecurityContextRepository());
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
