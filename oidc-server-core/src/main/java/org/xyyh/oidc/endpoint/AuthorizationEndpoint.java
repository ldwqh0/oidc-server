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
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;
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

    private String confirmAccessView = "oauth2/confirm_access";

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
     * ?????????????????????????????????
     */
    public void setConfirmAccessView(String confirmAccessView) {
        this.confirmAccessView = confirmAccessView;
    }

    /**
     * ??????????????????
     *
     * @param model         ????????????
     * @param clientIds     clientId
     * @param redirectUris  redirect ???????????????????????????oauth2
     * @param sessionStatus sessionStatus
     * @return ???????????????????????????
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
         * ??????????????????redirect uri????????????????????????????????????????????????client id ????????????????????????????????????
         */
        String clientId;
        String redirectUrl;
        ClientDetails client;
        // ???????????????client Id
        clientId = getClientId(clientIds);
        try {
            client = clientDetailsService.loadClientByClientId(clientId);
        } catch (NoSuchClientException e) {
            throw new UnauthorizedClientException(clientId, e);
        }
        // ???????????????redirectUri
        redirectUrl = getRedirectUri(redirectUris, clientId, client);
        OidcAuthorizationRequest authorizationRequest = OidcAuthorizationRequest.of(clientId, redirectUrl, params);
        // ??????client??????
        // ????????????????????????????????????????????????
        oAuth2RequestValidator.validate(authorizationRequest, client);
        // ???????????????????????????????????????
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
            // ??????????????????
            if (preResult.isApproved()) {
                sessionStatus.setComplete();
                return new ModelAndView(getAuthorizationSuccessRedirectView(authorizationRequest, preResult, client, userAuthentication));
            } else {
                model.put(OAUTH2_AUTHORIZATION_REQUEST, authorizationRequest);
                model.put(OAUTH2_AUTHORIZATION_CLIENT, client);
                // ????????????????????????????????????????????????
                return new ModelAndView(confirmAccessView, model);
            }
        }

    }

    /**
     * ????????????????????????clientId
     *
     * @param params ????????????
     * @throws UnauthorizedClientException ??????????????????????????????????????????
     */
    private String getClientId(List<String> params) throws UnauthorizedClientException {
        if (params.size() > 1) {
            throw new UnauthorizedClientException();
        } else {
            return params.get(0);
        }
    }

    /**
     * ???????????????????????????redirect uri
     *
     * @param params   ??????
     * @param clientId client id
     * @param client   client
     * @return ?????????????????????client id
     * @throws InvalidRedirectUriException ??????redirect uri????????????????????????
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
     * ????????????????????????,?????????????????????????????????<br>
     * ???????????????
     * ???????????? <a href="https://tools.ietf.org/html/rfc6749#section-4.1.1">https://tools.ietf.org/html/rfc6749#section-4.1.1</a>
     *
     * @param approvalParameters   ??????????????????
     * @param client               client??????
     * @param authorizationRequest ????????????
     * @param sessionStatus        sessionStatus
     * @param userAuthentication   ??????????????????
     * @return ??????????????????
     */
    @PostMapping(params = {USER_OAUTH_APPROVAL})
    public View approveOrDeny(
        @RequestParam Map<String, String> approvalParameters,
        @SessionAttribute(OAUTH2_AUTHORIZATION_CLIENT) ClientDetails client,
        @SessionAttribute(OAUTH2_AUTHORIZATION_REQUEST) OidcAuthorizationRequest authorizationRequest,
        Authentication userAuthentication,
        @AuthenticationPrincipal UserDetails user,
        SessionStatus sessionStatus) throws AccessDeniedException {
        // ???????????????????????????????????????session???????????????
        sessionStatus.setComplete();
        // ????????????????????????
        ApprovalResult approvalResult = userApprovalHandler.approval(authorizationRequest, user, approvalParameters);
        // ????????????????????????????????????
        if (!approvalResult.isApproved()) {
            throw new AccessDeniedException(authorizationRequest);
        } else {
            userApprovalHandler.updateAfterApproval(authorizationRequest, user, approvalResult);
            return getAuthorizationSuccessRedirectView(authorizationRequest, approvalResult, client, userAuthentication);
        }
    }

    /**
     * ?????????????????????
     *
     * @param request            ????????????
     * @param approvalResult     ????????????
     * @param userAuthentication ????????????
     * @param client             client
     * @return ?????????????????????????????????
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
            // ???????????????
            OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode();
            // ????????????????????????
            authorizationCode = authorizationCodeStorageService.save(authorizationCode, OidcAuthentication.of(request, approvalResult, client, userAuthentication));
            query.put("code", authorizationCode.getValue());
        }
        if (requestResponseTypes.contains(OidcAuthorizationResponseType.ID_TOKEN)) {
            System.out.println("bb");
            // TODO????????? id_token
        }
        return buildRedirectView(request.getRedirectUri(), query, null);
    }


    /**
     * ??????????????????
     *
     * @param uri       ????????????url
     * @param query     ?????????????????????????????????
     * @param fragments hash?????????????????????
     * @return ????????????
     */
    private View buildRedirectView(String uri, Map<String, String> query, Map<String, ?> fragments) {
        // ????????????????????????????????????url???
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
     * ??????client???????????????????????????????????????????????????
     *
     * @param ex ??????????????????
     */
    @ExceptionHandler({UnauthorizedClientException.class, InvalidRedirectUriException.class})
    public String handleError(Exception ex, WebRequest request) {
        request.setAttribute("error", ex, RequestAttributes.SCOPE_REQUEST);
        return "forward:/oauth2/error";
    }


    /**
     * ????????????????????????
     *
     * @param ex ??????????????????
     * @return ????????????
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
     * ???????????????
     */
    private OAuth2AuthorizationCode generateAuthorizationCode() {
        String codeValue = stringGenerator.generateKey();
        Instant issueAt = Instant.now();
        // code????????????????????????
        long periodOfValidity = 180;
        Instant expireAt = issueAt.plusSeconds(periodOfValidity);
        return OAuth2AuthorizationCode.of(codeValue, issueAt, expireAt);
    }
}

