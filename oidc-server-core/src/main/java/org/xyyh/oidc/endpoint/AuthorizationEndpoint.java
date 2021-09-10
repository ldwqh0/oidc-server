package org.xyyh.oidc.endpoint;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.client.ClientDetailsService;
import org.xyyh.oidc.collect.CollectionUtils;
import org.xyyh.oidc.collect.Maps;
import org.xyyh.oidc.core.*;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationResponseType;
import org.xyyh.oidc.exception.*;

import java.time.Instant;
import java.util.*;

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

    private String confirmAccessView = "oauth/confirm_access";

    public AuthorizationEndpoint(ClientDetailsService clientDetailsService,
                                 OAuth2AuthorizationRequestValidator requestValidator,
                                 UserApprovalHandler userApprovalHandler,
                                 OAuth2AuthorizationCodeStore authorizationCodeService) {
        this.clientDetailsService = clientDetailsService;
        this.oAuth2RequestValidator = requestValidator;
        this.userApprovalHandler = userApprovalHandler;
        this.authorizationCodeStorageService = authorizationCodeService;
    }

    /**
     * authorization_code
     * 指定授权确认页面的视图
     */
    public void setConfirmAccessView(String confirmAccessView) {
        this.confirmAccessView = confirmAccessView;
    }

    /**
     * 返回授权页面
     *
     * @param model         数据模型
     * @param clientIds     clientId
     * @param redirectUris  redirect 请求的回调地址，再oauth2
     * @param sessionStatus sessionStatus
     * @return 授权页面模型和视图
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-02#section-4.1.2.1">Authorization Response Error Response</a>
     */
    @RequestMapping(params = {OAuth2ParameterNames.RESPONSE_TYPE, OAuth2ParameterNames.CLIENT_ID})
    public ModelAndView authorize(
        Map<String, Object> model,
        Authentication userAuthentication,
        SessionStatus sessionStatus,
        @RequestParam(OAuth2ParameterNames.CLIENT_ID) List<String> clientIds,
        @RequestParam(value = OAuth2ParameterNames.REDIRECT_URI, required = false) List<String> redirectUris,
        @RequestParam MultiValueMap<String, String> params,
        @AuthenticationPrincipal UserDetails user) throws UnauthorizedClientException, InvalidRedirectUriException, InvalidRequestParameterException {
        /*
         * If the request fails due to a missing, invalid, or mismatching redirect URI,
         * or if the client identifier is missing or invalid,
         * the authorization server SHOULD inform the resource owner of the error
         * and MUST NOT automatically redirect the user-agent to the invalid redirect URI.
         *
         * 如果客户端的redirect uri错误，比如丢失，验证错误等，或者client id 不存在，不应该重定向页面
         */
        String clientId;
        String redirectUrl;
        ClientDetails client;
        // 获取并校验client Id
        clientId = getClientId(clientIds);
        try {
            client = clientDetailsService.loadClientByClientId(clientId);
        } catch (NoSuchClientException e) {
            throw new UnauthorizedClientException(clientId, e);
        }
        // 判断并校验redirectUri
        redirectUrl = getRedirectUri(redirectUris, clientId, client);
        OidcAuthorizationRequest authorizationRequest = OidcAuthorizationRequest.of(clientId, redirectUrl, params);
        // 加载client信息
        // 对请求进行检验，并抛出相应的异常
        oAuth2RequestValidator.validate(authorizationRequest, client);
        // 如果应用配置为直接通过授权
        if (client.isAutoApproval()) {
            sessionStatus.setComplete();
            return new ModelAndView(getAuthorizationSuccessRedirectView(
                authorizationRequest,
                ApprovalResult.of(authorizationRequest.getScopes(), authorizationRequest.getRedirectUri()),
                client,
                userAuthentication
            ));
        } else {
            ApprovalResult preResult = userApprovalHandler.preCheck(authorizationRequest, user);
            // 进行请求预检
            if (preResult.isApproved()) {
                sessionStatus.setComplete();
                return new ModelAndView(getAuthorizationSuccessRedirectView(authorizationRequest, preResult, client, userAuthentication));
            } else {
                model.put(OAUTH2_AUTHORIZATION_REQUEST, authorizationRequest);
                model.put(OAUTH2_AUTHORIZATION_CLIENT, client);
                // 如果预检没有通过，跳转到授权页面
                return new ModelAndView(confirmAccessView, model);
            }
        }

    }

    /**
     * 从请求参数中获取clientId
     *
     * @param params 参数列表
     * @throws UnauthorizedClientException 当参数数量错误时，抛出该异常
     */
    private String getClientId(List<String> params) throws UnauthorizedClientException {
        if (params.size() > 1) {
            throw new UnauthorizedClientException();
        } else {
            return params.get(0);
        }
    }

    /**
     * 获取并并校验请求的redirect uri
     *
     * @param params   参数
     * @param clientId client id
     * @param client   client
     * @return 获取到的有效的client id
     * @throws InvalidRedirectUriException 如果redirect uri无效，抛出该异常
     */
    private String getRedirectUri(List<String> params, String clientId, ClientDetails client) throws InvalidRedirectUriException {
        String redirectUrl;
        Set<String> registeredUris = client.getRegisteredRedirectUris();
        if (CollectionUtils.isEmpty(registeredUris)) {
            throw new InvalidRedirectUriException(clientId);
        }
        if (CollectionUtils.isEmpty(params)) {
            if (registeredUris.size() == 1) {
                redirectUrl = registeredUris.iterator().next();
            } else {
                throw new InvalidRedirectUriException(clientId);
            }
        } else if (params.size() > 1) {
            throw new InvalidRedirectUriException(clientId);
        } else {
            redirectUrl = params.get(0);
            if (!registeredUris.contains(redirectUrl)) {
                throw new InvalidRedirectUriException(clientId);
            }
        }
        return redirectUrl;
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
        @SessionAttribute(OAUTH2_AUTHORIZATION_REQUEST) OidcAuthorizationRequest authorizationRequest,
        Authentication userAuthentication,
        @AuthenticationPrincipal UserDetails user,
        SessionStatus sessionStatus) throws AccessDeniedException {
        // 当提交用户授权信息之后，将session标记为完成
        sessionStatus.setComplete();
        // 获取用户授权结果
        ApprovalResult approvalResult = userApprovalHandler.approval(authorizationRequest, user, approvalParameters);
        // 如果授权不通过，直接返回
        if (!approvalResult.isApproved()) {
            throw new AccessDeniedException(authorizationRequest);
        } else {
            userApprovalHandler.updateAfterApproval(authorizationRequest, user, approvalResult);
            return getAuthorizationSuccessRedirectView(authorizationRequest, approvalResult, client, userAuthentication);
        }
    }

    /**
     * 授权成功的跳转
     *
     * @param request            授权请求
     * @param approvalResult     授权结果
     * @param userAuthentication 用户信息
     * @param client             client
     * @return 授权成功之后跳转的地址
     */
    private View getAuthorizationSuccessRedirectView(OidcAuthorizationRequest request,
                                                     ApprovalResult approvalResult,
                                                     ClientDetails client,
                                                     Authentication userAuthentication) {
        Map<String, String> query = new LinkedHashMap<>();
        String state = request.getState();
        if (StringUtils.isNotEmpty(state)) {
            query.put("state", state);
        }
        Set<OidcAuthorizationResponseType> requestResponseTypes = request.getResponseTypes();
        if (requestResponseTypes.contains(OidcAuthorizationResponseType.CODE)) {
            // 创建授权码
            OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode();
            // 创建并保存授权码
            authorizationCode = authorizationCodeStorageService.save(authorizationCode, OidcAuthentication.of(request, approvalResult, client, userAuthentication));
            query.put("code", authorizationCode.getValue());
        }
        if (requestResponseTypes.contains(OidcAuthorizationResponseType.ID_TOKEN)) {
            System.out.println("bb");
            // TODO　添加 id_token
        }
        return buildRedirectView(request.getRedirectUri(), query, null);
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
        return new RedirectView(builder.toUriString());
    }

    /**
     * 处理client不存在存在的异常，这个异常不能跳转
     *
     * @param ex 要处理的异常
     */
    @ExceptionHandler({UnauthorizedClientException.class})
    public ModelAndView handleError(UnauthorizedClientException ex) {
//        sessionStatus.setComplete();
//        ex.getRequest()
        return new ModelAndView("/oauth2/error");
    }

    /**
     * 处理 InvalidRedirectUriException 异常，这个异常不能跳转
     *
     * @param ex 要处理的异常
     */
    @ExceptionHandler(InvalidRedirectUriException.class)
    public ModelAndView handleError(InvalidRedirectUriException ex) {
//        sessionStatus.setComplete();
        return new ModelAndView("/oauth2/error");
    }


    /**
     * 处理请求校验错误
     *
     * @param ex 要处理的异常
     * @return 异常视图
     */
    @ExceptionHandler({InvalidRequestParameterException.class})
    public ModelAndView handleError(InvalidRequestParameterException ex) throws UnauthorizedClientException {
        OidcAuthorizationRequest request = ex.getRequest();
        Map<String, String> error = Maps.hashMap();
        error.put("error", ex.getMessage());
        String state = request.getState();
        if (StringUtils.isNotEmpty(state)) {
            error.put("state", state);
        }
        return new ModelAndView(buildRedirectView(request.getRedirectUri(), error, null));
    }

    /**
     * 创建授权码
     */
    private OAuth2AuthorizationCode generateAuthorizationCode() {
        String codeValue = stringGenerator.generateKey();
        Instant issueAt = Instant.now();
        // code有效期默认三分钟
        long periodOfValidity = 180;
        Instant expireAt = issueAt.plusSeconds(periodOfValidity);
        return OAuth2AuthorizationCode.of(codeValue, issueAt, expireAt);
    }
}

