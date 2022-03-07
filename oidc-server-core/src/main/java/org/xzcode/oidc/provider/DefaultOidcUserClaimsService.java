package org.xzcode.oidc.provider;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.xzcode.oidc.core.OidcUserClaimsService;

/**
 * 一个简单的，实现 {@link UserDetails}向{@link OidcUserInfo}转换的
 */
public class DefaultOidcUserClaimsService implements OidcUserClaimsService {
    @Override
    public OidcUserInfo loadOidcUserInfo(UserDetails user) {
        return OidcUserInfo.builder()
                .subject(user.getUsername())
                .name(user.getUsername())
                .claim("roles", user.getAuthorities())
                .build();
    }
}
