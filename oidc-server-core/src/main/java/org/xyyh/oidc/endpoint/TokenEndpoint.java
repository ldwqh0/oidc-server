package org.xyyh.oidc.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.collect.Maps;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.converter.AccessTokenConverter;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.exception.RefreshTokenValidationException;
import org.xyyh.oidc.exception.TokenRequestValidationException;
import org.xyyh.oidc.utils.StringCollectionUtils;

import javax.validation.constraints.NotNull;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.xyyh.oidc.core.PkceValidator.CODE_CHALLENGE_METHOD_PLAIN;

/**
 * oauth2获取token的核心协议
 *
 * @see <a href=
 * "https://tools.ietf.org/html/rfc6749">https://tools.ietf.org/html/rfc6749</a>
 */
@RequestMapping("/oauth2/token")
public class TokenEndpoint {
    private static final String SPACE_REGEX = "[\\s+]";

    private final OAuth2AuthorizationCodeStore authorizationCodeService;

    private final OAuth2AuthorizationServerTokenService tokenService;

    private final AccessTokenConverter accessTokenConverter;

    private final PkceValidator pkceValidator;

    private final IdTokenGenerator idTokenGenerator;

    private final JWKSet jwkSet;

    public TokenEndpoint(OAuth2AuthorizationCodeStore authorizationCodeService,
                         OAuth2AuthorizationServerTokenService tokenService,
                         AccessTokenConverter accessTokenConverter,
                         PkceValidator pkceValidator,
                         IdTokenGenerator idTokenGenerator,
                         JWKSet jwkSet) {
        this.authorizationCodeService = authorizationCodeService;
        this.tokenService = tokenService;
        this.accessTokenConverter = accessTokenConverter;
        this.pkceValidator = pkceValidator;
        this.idTokenGenerator = idTokenGenerator;
        this.jwkSet = jwkSet;
    }

    @Autowired(required = false)
    public void setUserAuthenticationManager(AuthenticationManager userAuthenticationManager) {
    }

    /**
     * 不支持 get请求获取token,返回415状态码
     *
     * @return an empty {@link Map}
     */
    @GetMapping
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    // 暂不支持get请求u
    public Map<String, ?> getAccessToken() {
        return Collections.emptyMap();
    }

    /**
     * 授权码模式的授权请求
     *
     * @param client      连接信息
     * @param redirectUri 重定向uri
     * @return accessToken信息
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1">https://tools.ietf.org/html/rfc6749#section-4.1</a>
     */
    @PostMapping(params = {"code", "grant_type=authorization_code"})
    @ResponseBody
    public Map<String, Object> postAccessToken(
        @AuthenticationPrincipal(expression = "clientDetails") ClientDetails client,
        @RequestParam("code") String code,
        @RequestParam("redirect_uri") String redirectUri,
        @RequestParam MultiValueMap<String, String> requestParams) throws TokenRequestValidationException {
        // 使用http basic来验证client，通过AuthorizationServerSecurityConfiguration实现
        // 验证grant type
        validGrantTypes(client, "authorization_code");
        // 验证code
        // 首先验证code是否存在,没有找到指定的授权码信息时报错
        OidcAuthentication authentication = authorizationCodeService.consume(code)
            // 验证client是否匹配code所指定的client
            .filter(auth -> StringUtils.equals(client.getClientId(), auth.getClient().getClientId())
                // 颁发token时，redirect uri 必须和请求的redirect uri一致
                && StringUtils.equals(redirectUri, auth.getRequest().getRedirectUri()))
            .orElseThrow(() -> new TokenRequestValidationException("invalid_grant"));
        OidcAuthorizationRequest request = authentication.getRequest();
        // 根据请求进行pkce校验
        validPkce(request.getAdditionalParameters(), requestParams);
        // 签发token
        OAuth2ServerAccessToken accessToken = tokenService.createAccessToken(authentication);
        Map<String, Object> response = accessTokenConverter.toAccessTokenResponse(accessToken);
        if (request.getScopes().contains("openid")) {
            response.put("id_token", idTokenGenerator.generate(authentication.getUser(), accessToken, jwkSet.getKeyByKeyId("default-sign")));
        }
        return response;
    }


    /**
     * 刷新token
     *
     * @param refreshToken refreshToken
     * @param scope        scope
     * @return accessToken信息
     */
    @PostMapping(params = {"grant_type=refresh_token"})
    @ResponseBody
    public Map<String, Object> refreshToken(
        Authentication authentication,
        @AuthenticationPrincipal(expression = "clientDetails") ClientDetails client,
        @RequestParam("refresh_token") String refreshToken,
        @RequestParam(value = "scope", required = false) String scope
    ) throws TokenRequestValidationException {
        Set<String> requestScopes = StringCollectionUtils.split(scope);
        // 对token进行预检，如果检测失败，抛出异常
        try {
            OAuth2ServerAccessToken accessToken = tokenService.refreshAccessToken(refreshToken, client, requestScopes);
            return accessTokenConverter.toAccessTokenResponse(accessToken);
        } catch (RefreshTokenValidationException ex) {
            throw new TokenRequestValidationException("invalid_grant");
        }
    }

    @RequestMapping(params = {"grant_type=client_credentials"})
    public Map<String, Object> postAccessToken() {
        // TODO 客户端模式的的逻辑需要处理
        // 该模式下不能返回refresh_token
        return null;
    }

    /**
     * 其它不支持的授权类型
     *
     * @return 错误响应
     */
    @PostMapping
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, ?> otherwise() {
        Map<String, Object> response = Maps.hashMap();
        response.put("error", "unsupported_grant_type");
        return response;
    }

    /**
     * 处理异常请求
     *
     * @param ex 异常信息
     * @return 异常响应
     */
    @ExceptionHandler({TokenRequestValidationException.class})
    public ResponseEntity<Map<String, ?>> handleException(Exception ex) {
        Map<String, Object> response = Maps.hashMap();
        response.put("error", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
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
    @PostMapping("revoke")
    public void revoke(
        @RequestParam("token") String token,
        @RequestParam("token_type_hint") String tokenTypeHint,
        @AuthenticationPrincipal(expression = "clientDetails") ClientDetails client) {
        // TODO 需要支持跨域
        // TODO 待实现
        // 可能抛出 unsupported_token_type 异常
    }

    /**
     * 对请求进行pkce校验
     *
     * @param storeParams 储存的pkce参数
     * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636">Proof Key for Code Exchange by OAuth Public Clients</a>
     */
    private void validPkce(Map<String, String> storeParams, MultiValueMap<String, String> requestParams) throws TokenRequestValidationException {
        String codeChallenge = storeParams.get("code_challenge");
        if (StringUtils.isNotBlank(codeChallenge)) {
            String codeChallengeMethod = storeParams.get("code_challenge_method");// storeParams.getOrDefault("code_challenge_method", CODE_CHALLENGE_METHOD_PLAIN);
            if (StringUtils.isBlank(codeChallengeMethod)) {
                codeChallengeMethod = CODE_CHALLENGE_METHOD_PLAIN;
            }
            String codeVerifier = requestParams.getFirst("code_verifier");
            pkceValidator.validate(codeChallenge, codeVerifier, codeChallengeMethod);
        }
    }


    private void validGrantTypes(ClientDetails client, @NotNull String grantType) throws TokenRequestValidationException {
        Set<AuthorizationGrantType> grantTypes = client.getAuthorizedGrantTypes();
        if (grantTypes.stream().map(AuthorizationGrantType::getValue).noneMatch(grantType::equals)) {
            throw new TokenRequestValidationException("unauthorized_client");
        }
    }
}
