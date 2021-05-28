package org.xyyh.oidc.server.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.xyyh.oidc.core.OAuth2ResourceServerTokenService;
import org.xyyh.oidc.core.OidcAuthentication;

import java.util.Optional;

public class ServerOpaqueTokenAuthenticationManager implements AuthenticationManager {

    private final OAuth2ResourceServerTokenService tokenService;

    public ServerOpaqueTokenAuthenticationManager(OAuth2ResourceServerTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof BearerTokenAuthenticationToken) {
            String token = ((BearerTokenAuthenticationToken) authentication).getToken();
            Optional<OidcAuthentication> storedAuthentication = this.tokenService.loadAuthentication(token);
            return storedAuthentication.map(it -> OidcAuthentication.from(it, authentication.getDetails())).orElse(null);
        } else {
            return null;
        }
    }
}
