package org.xyyh.oidc.endpoint;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.web.bind.annotation.*;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.client.ClientDetails.ClientType;
import org.xyyh.oidc.client.ClientDetailsService;
import org.xyyh.oidc.collect.Maps;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.converter.AccessTokenConverter;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.exception.ClientUnauthorizedException;
import org.xyyh.oidc.exception.RefreshTokenValidationException;
import org.xyyh.oidc.exception.TokenRequestValidationException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
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

    private final JWKSet jwkSet;

    private final ClientDetailsService clientDetailsService;

    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    public TokenEndpoint(OAuth2AuthorizationCodeStore authorizationCodeService,
                         OAuth2AuthorizationServerTokenService tokenService,
                         AccessTokenConverter accessTokenConverter,
                         PkceValidator pkceValidator,
                         IdTokenGenerator idTokenGenerator,
                         JWKSet jwkSet, ClientDetailsService clientDetailsService) {
        this.authorizationCodeService = authorizationCodeService;
        this.tokenService = tokenService;
        this.accessTokenConverter = accessTokenConverter;
        this.pkceValidator = pkceValidator;
        this.idTokenGenerator = idTokenGenerator;
        this.jwkSet = jwkSet;
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * @param code        授权码
     * @param redirectUri 重定向uri
     * @param httpRequest http请求信息
     * @throws TokenRequestValidationException 如果校验失败，抛出该异常
     * @throws JOSEException                   生成 id-token错误时，引发该异常
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1">https://tools.ietf.org/html/rfc6749#section-4.1</a>
     */
    @ResponseBody
    @PostMapping(params = {"code", "grant_type=authorization_code"})
    public Map<String, Object> postAccessToken(
        @RequestParam("code") String code,
        @RequestParam("redirect_uri") String redirectUri,
        @RequestHeader("host") String host,
        @RequestParam(value = "client_id") String clientId,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
        @RequestParam(value = "code_verifier", required = false) String codeVerifier,
        @RequestParam(value = "code_challenge_method", required = false, defaultValue = CODE_CHALLENGE_METHOD_PLAIN) String code_challenge_method,
        HttpServletRequest httpRequest) throws TokenRequestValidationException, JOSEException, ClientUnauthorizedException {
        final ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
        if (Objects.isNull(client)) {
            // TODO 异常类型待确定
            throw new TokenRequestValidationException("invalid_client");
        }
        if (!ClientType.CLIENT_PUBLIC.equals(client.getType())) {
            validateClientAuthentication(clientId, authorizationHeader);
        }

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
        Map<String, String> storeParams = storedRequest.getParameters();
        // 如果是public应用，需要验证pkce
        if (ClientType.CLIENT_PUBLIC.equals(client.getType())) {
            String codeChallenge = storeParams.get("code_challenge");
            pkceValidator.validate(codeChallenge, codeVerifier, code_challenge_method);
        }

        // 签发token
        OAuth2ServerAccessToken accessToken = tokenService.createAccessToken(authentication);
        Map<String, Object> response = accessTokenConverter.toAccessTokenResponse(accessToken);
        if (storedRequest.getScopes().contains(OidcScopes.OPENID)) {
            // TODO 这里其实有待商榷
            String scheme = httpRequest.getScheme();
            String issuer = StringUtils.join(scheme, "://", host, "/oauth2");
            String token = idTokenGenerator.generate(issuer, (UserDetails) Objects.requireNonNull(authentication.getUser()).getPrincipal(), accessToken, storedRequest, jwkSet.getKeyByKeyId("default-sign"));
            response.put("id_token", token);
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
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
        @RequestParam("refresh_token") String refreshToken,
        @RequestParam(value = "scope", required = false) String scope
    ) throws TokenRequestValidationException, ClientUnauthorizedException {
        Set<String> requestScopes = new HashSet<>(Arrays.asList(StringUtils.split(scope)));
        // 对token进行预检，如果检测失败，抛出异常
        try {
            // 获取这个refresh token已经存在的client
            ClientDetails client = tokenService.loadAuthenticationByRefreshToken(refreshToken)
                .map(OidcAuthentication::getClient)
                // token已经过期了
                .orElseThrow(() -> new TokenRequestValidationException("invalid_request"));
            // 如果client type不是公共的，需要验证client的密码
            if (!ClientType.CLIENT_PUBLIC.equals(client.getType())) {
                client = validateClientAuthentication(client.getClientId(), authorizationHeader);
            }
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
    }

    /**
     * 如果客户端认证不通过，抛出该异常
     */
    @ResponseBody
    @ExceptionHandler({ClientUnauthorizedException.class})
    public ResponseEntity<Void> handleClientUnauthorized(ClientUnauthorizedException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .header("WWW-Authenticate", "Realm").build();
    }

    private void validGrantTypes(ClientDetails client, @NotNull AuthorizationGrantType grantType) throws TokenRequestValidationException {
        Set<AuthorizationGrantType> grantTypes = client.getAuthorizedGrantTypes();
        if (!grantTypes.contains(grantType)) {
            throw new TokenRequestValidationException("unsupported_grant_type");
        }
    }

    private ClientDetails validateClientAuthentication(String clientId, String header) throws ClientUnauthorizedException {
        // 如果不是 public client,需要验证Client security
        UsernamePasswordAuthenticationToken clientToken;
        try {
            clientToken = converterAuthenticationHeader(header);
        } catch (Exception e) {
            throw new ClientUnauthorizedException("invalid_client");
        }
        if (Objects.isNull(clientToken)) {
            throw new ClientUnauthorizedException("invalid_client");
        }
        if (!Objects.equals(clientId, clientToken.getName())) {
            throw new ClientUnauthorizedException("invalid_client");
        }

        // 两次
        ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
        if (!Objects.equals(client.getPassword(), clientToken.getCredentials())) {
            // 需要返回401
            throw new ClientUnauthorizedException("invalid_client");
        }
        return client;
    }

    private UsernamePasswordAuthenticationToken converterAuthenticationHeader(String header) {
        header = header.trim();
        if (!org.springframework.util.StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
            return null;
        }
        if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
            throw new BadCredentialsException("Empty basic authentication token");
        }
        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded = decode(base64Token);
        String token = new String(decoded, StandardCharsets.UTF_8);
        int delim = token.indexOf(":");
        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new UsernamePasswordAuthenticationToken(token.substring(0, delim), token.substring(delim + 1));
    }

    private byte[] decode(byte[] base64Token) {
        try {
            return Base64.getDecoder().decode(base64Token);
        } catch (IllegalArgumentException ex) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }
    }
}
