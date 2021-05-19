package org.xyyh.oidc.userdetails;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public interface OidcUserDetails extends UserDetails, OAuth2User {

    String getSubject();

    Map<String, Object> getClaims();
}
