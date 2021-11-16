package org.xyyh.oidc.core;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.*;
import static org.xyyh.oidc.core.MapUtils.copyValueByKey;

public interface OidcUserClaimsService {
    OidcUserInfo loadOidcUserInfo(UserDetails user);

    default Map<String, ?> loadClaims(OidcAuthentication authentication) {
        Set<String> scopes = authentication.getScopes();
        UserDetails user = (UserDetails) authentication.getPrincipal();
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> userClaims = this.loadOidcUserInfo(user).getClaims();
        copyValueByKey(userClaims, result, SUB);
        if (scopes.contains(OidcScopes.PROFILE)) {
            copyValueByKey(userClaims, result,
                    NAME, GIVEN_NAME, FAMILY_NAME, MIDDLE_NAME, NICKNAME, PREFERRED_USERNAME,
                    PROFILE, PICTURE, WEBSITE, GENDER, BIRTHDATE,
                    ZONEINFO, LOCALE, UPDATED_AT
            );
            result.put("roles", user.getAuthorities());
        }
        if (scopes.contains(OidcScopes.EMAIL)) {
            copyValueByKey(userClaims, result, EMAIL, EMAIL_VERIFIED);
        }
        // TODO 地址是个嵌套结构，需要单独处理一下
        if (scopes.contains(OidcScopes.ADDRESS)) {
            copyValueByKey(userClaims, result, ADDRESS);
        }
        if (scopes.contains(OidcScopes.PHONE)) {
            copyValueByKey(userClaims, result, PHONE_NUMBER, PHONE_NUMBER_VERIFIED);
        }
        return result;
    }
}

final class MapUtils {
    private MapUtils() {

    }

    public static void copyValueByKey(Map<String, Object> source, Map<String, Object> target, String... names) {
        for (String name : names) {
            Object value = source.get(name);
            if (ObjectUtils.isNotEmpty(value)) {
                target.put(name, value);
            }
        }
    }
}

