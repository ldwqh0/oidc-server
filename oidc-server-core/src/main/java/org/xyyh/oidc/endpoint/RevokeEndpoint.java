package org.xyyh.oidc.endpoint;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.core.OAuth2AuthorizationServerTokenService;

@RequestMapping("revoke")
public class RevokeEndpoint {

    private final OAuth2AuthorizationServerTokenService tokenService;

    public RevokeEndpoint(OAuth2AuthorizationServerTokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * revoke a token<br>
     * 废除一token,可以是access token,也可以是refresh token
     *
     * @param token         要移除的token的值
     * @param tokenTypeHint tokenTypeHint
     * @param client        client信息
     * @see <a href=
     * "https://tools.ietf.org/html/rfc7009#section-2.1">https://tools.ietf.org/html/rfc7009#section-2.1</a>
     */
    @PostMapping
    public void revoke(
        @RequestParam("token") String token,
        @RequestParam("token_type_hint") String tokenTypeHint,
        @AuthenticationPrincipal ClientDetails client) {
        // TODO 需要支持跨域
        // TODO 待实现
        // 可能抛出 unsupported_token_type 异常
        tokenService.revokeAccessToken(token);
    }

}
