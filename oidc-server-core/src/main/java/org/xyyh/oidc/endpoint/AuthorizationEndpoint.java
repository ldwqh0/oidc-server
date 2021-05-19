package org.xyyh.oidc.endpoint;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.client.ClientDetailsService;
import org.xyyh.oidc.collect.Maps;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.converter.AccessTokenConverter;
import org.xyyh.oidc.endpoint.request.OpenidAuthorizationFlow;
import org.xyyh.oidc.endpoint.request.OpenidAuthorizationRequest;
import org.xyyh.oidc.exception.*;
import org.xyyh.oidc.userdetails.OidcUserDetails;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

@SessionAttributes({"authorizationRequest", "authorizationClient"})
@RequestMapping("/oauth2/authorize")
public class AuthorizationEndpoint {

    private static final String OAUTH2_AUTHORIZATION_REQUEST = "authorizationRequest";
    private static final String OAUTH2_AUTHORIZATION_CLIENT = "authorizationClient";
    private static final String USER_OAUTH_APPROVAL = "user_oauth_approval";

    private final StringKeyGenerator stringGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder(), 33);

    private final ClientDetailsService clientDetailsService;

    private final OAuth2AuthorizationRequestValidator oAuth2RequestValidator;

    private final UserApprovalHandler userApprovalHandler;

    private final OAuth2AuthorizationCodeStore authorizationCodeStorageService;

    private final OAuth2AuthorizationServerTokenService tokenServices;

    private final AccessTokenConverter accessTokenConverter;

    private String confirmAccessView = "oauth/confirm_access";

    public AuthorizationEndpoint(ClientDetailsService clientDetailsService,
                                 OAuth2AuthorizationRequestValidator requestValidator,
                                 UserApprovalHandler userApprovalHandler,
                                 OAuth2AuthorizationCodeStore authorizationCodeService,
                                 OAuth2AuthorizationServerTokenService tokenServices,
                                 AccessTokenConverter accessTokenConverter) {
        this.clientDetailsService = clientDetailsService;
        this.oAuth2RequestValidator = requestValidator;
        this.userApprovalHandler = userApprovalHandler;
        this.authorizationCodeStorageService = authorizationCodeService;
        this.tokenServices = tokenServices;
        this.accessTokenConverter = accessTokenConverter;
    }

    /**
     * 指定授权确认页面的视图
     */
    public void setConfirmAccessView(String confirmAccessView) {
        this.confirmAccessView = confirmAccessView;
    }

    /**
     * 返回授权页面
     *
     * @param model         数据模型
     * @param sessionStatus sessionStatus
     * @return 授权页面模型和视图
     */
    @RequestMapping(params = {OAuth2ParameterNames.RESPONSE_TYPE, OAuth2ParameterNames.CLIENT_ID})
    public ModelAndView authorize(
        WebRequest request,
        Map<String, Object> model,
        @RequestParam MultiValueMap<String, String> params,
        @AuthenticationPrincipal OidcUserDetails user,
        SessionStatus sessionStatus) throws OpenidRequestValidationException {
        // 保存请求信息
        OpenidAuthorizationRequest authorizationRequest = OpenidAuthorizationRequest.of(request.getContextPath(), params);
        try {
            // 加载client信息
            ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
            // 对请求进行检验，并抛出相应的异常
            oAuth2RequestValidator.validate(authorizationRequest, client);

            // 如果应用配置为直接通过授权
            if (client.isAutoApproval()) {
                sessionStatus.setComplete();
                return new ModelAndView(getAuthorizationSuccessRedirectView(
                    authorizationRequest,
                    ApprovalResult.of(authorizationRequest.getScopes(), authorizationRequest.getRedirectUri()),
                    client,
                    user
                ));
            } else {
                ApprovalResult preResult = userApprovalHandler.preCheck(authorizationRequest, user);
                // 进行请求预检
                if (preResult.isApproved()) {
                    sessionStatus.setComplete();
                    return new ModelAndView(getAuthorizationSuccessRedirectView(authorizationRequest, preResult, client, user));
                } else {
                    model.put(OAUTH2_AUTHORIZATION_REQUEST, authorizationRequest);
                    model.put(OAUTH2_AUTHORIZATION_CLIENT, client);
                    // 如果预检没有通过，跳转到授权页面
                    return new ModelAndView(confirmAccessView, model);
                }
            }
        } catch (NoSuchClientException ex) {
            throw new OpenidRequestValidationException(authorizationRequest, "unauthorized_client");
        } catch (InvalidScopeException ex2) {
            throw new OpenidRequestValidationException(authorizationRequest, "invalid_scope");
        } catch (UnsupportedResponseTypeException ex3) {
            throw new OpenidRequestValidationException(authorizationRequest, "unsupported_response_type");
        } catch (UnRegisteredRedirectUriException ex4) {
            throw new OpenidRequestValidationException(authorizationRequest, "invalid_redirect_uri");
        }
    }


    /**
     * 提交授权验证请求,并返回授权验证结果视图<br>
     * 默认的收钱
     * 具体参见 <a href="https://tools.ietf.org/html/rfc6749#section-4.1.1">https://tools.ietf.org/html/rfc6749#section-4.1.1</a>
     *
     * @param approvalParameters   授权验证参数
     * @param client               client信息
     * @param authorizationRequest 请求信息
     * @param sessionStatus        sessionStatus
     * @param userAuthentication   当前用户信息
     * @return 验证结果视图
     */
    @PostMapping(params = {USER_OAUTH_APPROVAL})
    public View approveOrDeny(
        @RequestParam Map<String, String> approvalParameters,
        @SessionAttribute(OAUTH2_AUTHORIZATION_CLIENT) ClientDetails client,
        @SessionAttribute(OAUTH2_AUTHORIZATION_REQUEST) OpenidAuthorizationRequest authorizationRequest,
        @AuthenticationPrincipal OidcUserDetails userAuthentication,
        SessionStatus sessionStatus) throws OpenidRequestValidationException {
        // 当提交用户授权信息之后，将session标记为完成
        sessionStatus.setComplete();
        // 获取用户授权结果
        ApprovalResult approvalResult = userApprovalHandler.approval(authorizationRequest, userAuthentication, approvalParameters);
        // 如果授权不通过，直接返回
        if (!approvalResult.isApproved()) {
            throw new OpenidRequestValidationException(authorizationRequest, "access_denied");
        } else {
            userApprovalHandler.updateAfterApproval(authorizationRequest, userAuthentication, approvalResult);
            return getAuthorizationSuccessRedirectView(authorizationRequest, approvalResult, client, userAuthentication);
        }
    }

    /**
     * 授权成功的跳转
     *
     * @param authorizationRequest 授权请求
     * @param approvalResult       授权结果
     * @param user                 用户信息
     * @param client               client
     * @return 授权成功之后跳转的地址
     */
    private View getAuthorizationSuccessRedirectView(OpenidAuthorizationRequest authorizationRequest,
                                                     ApprovalResult approvalResult,
                                                     ClientDetails client,
                                                     OidcUserDetails user) {
        OpenidAuthorizationFlow flow = authorizationRequest.getFlow();
        if (OpenidAuthorizationFlow.CODE.equals(flow)) {
            return getCodeFlowResponse(authorizationRequest, approvalResult, client, user);
        } else if (OpenidAuthorizationFlow.IMPLICIT.equals(flow)) {
            // 简易模式的token请求 https://tools.ietf.org/html/rfc6749#section-4.2
            return getImplicitFlowResponse(authorizationRequest, approvalResult, client, user);
        } else if (OpenidAuthorizationFlow.HYBRID.equals(flow)) {
            return getHybridFlow(authorizationRequest, approvalResult, user);
        }
        throw new RuntimeException("no flow can be find");
    }

    /**
     * 创建简易模式跳转请求 参考 <a href="https://tools.ietf.org/html/rfc6749#section-4.2">https://tools.ietf.org/html/rfc6749#section-4.2</a><br>
     * 简易模式下，不能返回refresh_token
     *
     * @param request 授权请求
     * @param result  授权结果
     * @param user    授权用户
     * @param client  c
     * @return 跳转视图
     */
    private View getImplicitFlowResponse(OpenidAuthorizationRequest request,
                                         ApprovalResult result,
                                         ClientDetails client,
                                         OidcUserDetails user) {
        OidcAuthentication authentication = OidcAuthentication.of(request, result, client, user);
        OAuth2ServerAccessToken accessToken = tokenServices.createAccessToken(authentication);

        Map<String, Object> fragment = accessTokenConverter.toAccessTokenResponse(accessToken);
        String state = request.getState();
        if (StringUtils.isNotBlank(state)) {
            fragment.put("state", state);
        }
        // 简易模式下，不能返回refresh token
        return buildRedirectView(request.getRedirectUri(), null, fragment);
    }

    /**
     * 创建授权码请求的view
     *
     * @param request 授权请求信息
     * @param result  预验证结果
     * @param client
     * @param user    用户权限信息
     * @return 授权视图
     * @see @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636">Proof Key for Code Exchange by OAuth Public Clients</a>
     */
    private View getCodeFlowResponse(
        OpenidAuthorizationRequest request,
        ApprovalResult result,
        ClientDetails client,
        OidcUserDetails user) {
        Map<String, String> query = new LinkedHashMap<>();
        String state = request.getState();
        if (StringUtils.isNotEmpty(state)) {
            query.put("state", state);
        }
        // 创建授权码
        OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode();
        // 创建并保存授权码
        authorizationCode = authorizationCodeStorageService.save(authorizationCode, OidcAuthentication.of(request, result, client, user));
        query.put("code", authorizationCode.getValue());
        return buildRedirectView(request.getRedirectUri(), query, null);
    }

    /**
     * 返回混合模式认证的视图
     *
     * @param authorizationRequest 授权请求
     * @param approvalResult       用户授权结果
     * @param user                 用户信息
     * @return 混合授权模式视图
     */
    private View getHybridFlow(OpenidAuthorizationRequest authorizationRequest,
                               ApprovalResult approvalResult,
                               OidcUserDetails user) {
        // TODO 待实现
        return null;
    }

    /**
     * 创建跳转请求
     *
     * @param uri       要跳转的url
     * @param query     需要额外增加的查询参数
     * @param fragments hash部分的参数列表
     * @return 跳转视图
     */
    private View buildRedirectView(String uri, Map<String, String> query, Map<String, ?> fragments) {
        // 将新构建的查询参数附加到url上
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri);
        if (Maps.isNotEmpty(query)) {
            query.forEach(builder::queryParam);
        }
        if (Maps.isNotEmpty(fragments)) {
            StringBuilder fragmentValues = new StringBuilder();
            String originFragment = builder.build().getFragment();
            if (StringUtils.isNotBlank(originFragment)) {
                fragmentValues.append(originFragment);
            }
            fragments.forEach((key, value) -> {
                if (fragmentValues.length() > 0) {
                    fragmentValues.append("&");
                }
                fragmentValues.append(key);
                if (ObjectUtils.isNotEmpty(value)) {
                    fragmentValues.append("=").append(value);
                }
            });
            builder.fragment(fragmentValues.toString());
        }
        RedirectView redirectView = new RedirectView(builder.toUriString());
        redirectView.setStatusCode(HttpStatus.SEE_OTHER);
        return redirectView;
    }


    /**
     * 处理请求校验错误
     *
     * @param ex 要处理的异常
     * @return 异常视图
     */
    @ExceptionHandler({OpenidRequestValidationException.class})
    public View handleError(OpenidRequestValidationException ex, SessionStatus sessionStatus) {
        sessionStatus.setComplete();
        OpenidAuthorizationRequest authorizationRequest = ex.getRequest();
        Map<String, String> error = Maps.hashMap();
        error.put("error", ex.getMessage());
        String state = authorizationRequest.getState();
        if (StringUtils.isNotEmpty(state)) {
            error.put("state", state);
        }
        OpenidAuthorizationRequest request = ex.getRequest();
        String redirect = Objects.isNull(request) ? null : request.getRedirectUri();
        return buildRedirectView(redirect, error, null);
    }


    private OAuth2AuthorizationCode generateAuthorizationCode() {
        String codeValue = stringGenerator.generateKey();
        Instant issueAt = Instant.now();
        // code有效期默认三分钟
        long periodOfValidity = 180;
        Instant expireAt = issueAt.plusSeconds(periodOfValidity);
        return OAuth2AuthorizationCode.of(codeValue, issueAt, expireAt);
    }
}
