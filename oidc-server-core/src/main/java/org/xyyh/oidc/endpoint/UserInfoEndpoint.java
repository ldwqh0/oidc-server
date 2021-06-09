package org.xyyh.oidc.endpoint;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xyyh.oidc.core.OidcAuthentication;
import org.xyyh.oidc.core.OidcUserInfoService;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.*;

/**
 * 获取用户信息的端点
 */
@RestController
@RequestMapping("/oauth2/userinfo")
public class UserInfoEndpoint {

    private static final String USER_ROLE = "roles";

    private final OidcUserInfoService userClaimsService;

    public UserInfoEndpoint(OidcUserInfoService userClaimsService) {
        this.userClaimsService = userClaimsService;
    }

    /**
     * 获取用户信息
     *
     * @param authentication oauth2授权信息
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
     */
    @GetMapping
    public Map<String, ?> getUserInfo(OidcAuthentication authentication) {
        Set<String> scopes = authentication.getScopes();
        UserDetails user = (UserDetails) Objects.requireNonNull(authentication.getUser()).getPrincipal();
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> userClaims = userClaimsService.loadOidcUserInfo(user).getClaims();
        copyValueByKey(userClaims, result, SUB);
        if (scopes.contains(OidcScopes.PROFILE)) {
            copyValueByKey(userClaims, result,
                NAME, GIVEN_NAME, FAMILY_NAME, MIDDLE_NAME, NICKNAME, PREFERRED_USERNAME,
                PROFILE, PICTURE, WEBSITE, GENDER, BIRTHDATE,
                ZONEINFO, LOCALE, UPDATED_AT
            );
            result.put(USER_ROLE, user.getAuthorities());
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

    private void copyValueByKey(Map<String, Object> source, Map<String, Object> target, String... names) {
        for (String name : names) {
            Object value = source.get(name);
            if (ObjectUtils.isNotEmpty(value)) {
                target.put(name, value);
            }
        }
    }
}
