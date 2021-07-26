package org.xyyh.oidc.endpoint;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.collect.Maps;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.converter.AccessTokenConverter;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.exception.RefreshTokenValidationException;
import org.xyyh.oidc.exception.TokenRequestValidationException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.*;

import static org.xyyh.oidc.core.PkceValidator.CODE_CHALLENGE_METHOD_PLAIN;

/**
 * oauth2获取token的核心协议
 *
 * @see <a href=
 * "https://tools.ietf.org/html/rfc6749">https://tools.ietf.org/html/rfc6749</a>
 */
@RequestMapping("/oauth2/token")
public class TokenEndpoint {

    private final OAuth2AuthorizationCodeStore authorizationCodeService;

    private final OAuth2AuthorizationServerTokenService tokenService;

    private final AccessTokenConverter accessTokenConverter;

    private final PkceValidator pkceValidator;

    private final IdTokenGenerator idTokenGenerator;

//    private final JWKSet jwkSet;

    private final JWK jwk;

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
        this.jwk = jwkSet.getKeys().get(0);
//        this.jwkSet = jwkSet;
    }

    /**
     * @param client        连接信息
     * @param code          授权码
     * @param redirectUri   重定向uri
     * @param requestParams 请求参数
     * @param httpRequest   http请求信息
     * @return
     * @throws TokenRequestValidationException 如果校验失败，抛出该异常
     * @throws JOSEException                   生成 id-token错误时，引发该异常
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1">https://tools.ietf.org/html/rfc6749#section-4.1</a>
     */
    @PostMapping(params = {"code", "grant_type=authorization_code"})
    @ResponseBody
    public ResponseEntity<?> postAccessToken(
        @AuthenticationPrincipal ClientDetails client,
        @RequestParam("code") String code,
        @RequestParam("redirect_uri") String redirectUri,
        @RequestParam MultiValueMap<String, String> requestParams,
        @RequestHeader("host") String host,
        HttpServletRequest httpRequest) throws TokenRequestValidationException, JOSEException {
        // 使用http basic来验证client，通过AuthorizationServerSecurityConfiguration实现
        // 验证grant type
        validGrantTypes(client, AuthorizationGrantType.AUTHORIZATION_CODE);
        // 验证code
        // 首先验证code是否存在,没有找到指定的授权码信息时报错
        OidcAuthentication authentication = authorizationCodeService.consume(code)
            // 验证client是否匹配code所指定的client
            .filter(auth -> StringUtils.equals(client.getClientId(), auth.getClient().getClientId())
                // 颁发token时，redirect uri 必须和请求的redirect uri一致
                && StringUtils.equals(redirectUri, auth.getRequest().getRedirectUri()))
            .orElseThrow(() -> new TokenRequestValidationException("invalid_grant"));
        OidcAuthorizationRequest storedRequest = authentication.getRequest();
        // 根据请求进行pkce校验,如果是公共客户端，一定要进行pkce校验
        if (ClientDetails.ClientType.CLIENT_PUBLIC.equals(client.getType())) {
            validPkce(storedRequest.getParameters(), requestParams);
        }
        // 签发token
        OAuth2ServerAccessToken accessToken = tokenService.createAccessToken(authentication);
        Map<String, Object> response = accessTokenConverter.toAccessTokenResponse(accessToken);
        if (storedRequest.getScopes().contains(OidcScopes.OPENID)) {
            // TODO 这里其实有待商榷
            String scheme = httpRequest.getScheme();
            String issuer = StringUtils.join(scheme, "://", host, "/oauth2");
            String token = idTokenGenerator.generate(issuer, (UserDetails) Objects.requireNonNull(authentication.getUser()).getPrincipal(), accessToken, storedRequest, jwk);
            response.put("id_token", token);
        }
        // 构建跨域信息，仅仅允许来自redirect的跨域请求
        URI uri = URI.create(storedRequest.getRedirectUri());
        StringBuilder origin = new StringBuilder();
        origin.append(uri.getScheme()).append("://");
        origin.append(uri.getHost());
        int port = uri.getPort();
        if (port > 0) {
            origin.append(":").append(port);
        }
        return ResponseEntity.ok().header("Access-Control-Allow-Origin", origin.toString()).body(response);
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
        @AuthenticationPrincipal ClientDetails client,
        @RequestParam("refresh_token") String refreshToken,
        @RequestParam(value = "scope", required = false) String scope
    ) throws TokenRequestValidationException {
        Set<String> requestScopes = new HashSet<>(Arrays.asList(StringUtils.split(scope)));
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
    @ResponseBody
    @ExceptionHandler({TokenRequestValidationException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, ?> handleException(Exception ex) {
        Map<String, Object> response = Maps.hashMap();
        response.put("error", ex.getMessage());
        return response;
//        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
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


    private void validGrantTypes(ClientDetails client, @NotNull AuthorizationGrantType grantType) throws TokenRequestValidationException {
        Set<AuthorizationGrantType> grantTypes = client.getAuthorizedGrantTypes();
        if (!grantTypes.contains(grantType)) {
            throw new TokenRequestValidationException("unsupported_grant_type");
        }
    }
}
