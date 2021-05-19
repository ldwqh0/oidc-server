package org.xyyh.oidc.userdetails;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface OidcUserDetailsService extends UserDetailsService {

    @Override
    OidcUserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
