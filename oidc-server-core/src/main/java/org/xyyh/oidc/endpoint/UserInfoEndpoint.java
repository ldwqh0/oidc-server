package org.xyyh.oidc.endpoint;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xyyh.oidc.userdetails.OidcUserDetails;

import java.util.HashMap;
import java.util.Map;

/**
 * 获取用户信息的端点
 */
@RestController
@RequestMapping("/oauth2/userinfo")
public class UserInfoEndpoint {

    /**
     * 获取用户信息
     *
     * @param user
     * @return
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
     */
    @GetMapping
    public Object getUserInfo(@AuthenticationPrincipal OidcUserDetails user) {
//        user.
        Map<String, Object> result = new HashMap<>();
        result.put(StandardClaimNames.SUB, user.getSubject());
        return result;
    }

}
