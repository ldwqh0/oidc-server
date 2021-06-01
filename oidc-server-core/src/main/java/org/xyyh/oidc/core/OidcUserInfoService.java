package org.xyyh.oidc.core;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

public interface OidcUserInfoService {
    OidcUserInfo loadOidcUserInfo(UserDetails user);
}
