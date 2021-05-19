package org.xyyh.oidc.provider;

import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.xyyh.oidc.userdetails.OidcUserDetails;
import org.xyyh.oidc.userdetails.OidcUserDetailsService;

public class PreAuthenticatedProvider implements AuthenticationProvider {

    private final OidcUserDetailsService userDetailsService;

    private final UserDetailsChecker userChecker = new AccountStatusUserDetailsChecker();

    public PreAuthenticatedProvider(OidcUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }
        String username = authentication.getName();
        OidcUserDetails userDetails = userDetailsService.loadUserByUsername(username);
        userChecker.check(userDetails);
        PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(userDetails, userDetails.getAuthorities());
        result.setAuthenticated(true);
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
