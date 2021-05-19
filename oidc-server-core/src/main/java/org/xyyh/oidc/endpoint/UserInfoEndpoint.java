package org.xyyh.oidc.endpoint;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xyyh.oidc.userdetails.OidcUserDetails;

@RequestMapping("/oauth2/userinfo")
@RestController
public class UserInfoEndpoint {

    @GetMapping
    public Object getUserInfo(@AuthenticationPrincipal OidcUserDetails user) {
//        user.

        return user;
    }

}
