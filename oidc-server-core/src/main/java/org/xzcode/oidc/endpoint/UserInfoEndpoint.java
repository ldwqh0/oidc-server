package org.xzcode.oidc.endpoint;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.xzcode.oidc.core.OidcAuthentication;
import org.xzcode.oidc.core.OidcUserClaimsService;

import java.util.Map;

/**
 * 获取用户信息的端点
 */
@RequestMapping("/oauth2/userinfo")
public class UserInfoEndpoint {

    private final OidcUserClaimsService userClaimsService;

    public UserInfoEndpoint(OidcUserClaimsService userClaimsService) {
        this.userClaimsService = userClaimsService;
    }

    /**
     * 获取用户信息
     *
     * @param authentication oauth2授权信息
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
     */
    @GetMapping
    @ResponseBody
    public Map<String, ?> getUserInfo(OidcAuthentication authentication) {
        return userClaimsService.loadClaims(authentication);
    }

}
