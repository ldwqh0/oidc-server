package org.xyyh.oidc.endpoint.request;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;
import org.xyyh.oidc.collect.CollectionUtils;
import org.xyyh.oidc.exception.InvalidRequestParameterException;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 一个可以包含openid请求参数的请求封装<br>
 * openid 和oauth2 请求的区别在于，openid请求的 response_type 参数是以空格分割的多个参数
 * 也就是是 openid 的 Hybrid Flow
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-02#section-3.1">Authorization Endpoint</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth">Authentication using the Hybrid Flow</a>
 */
public class OidcAuthorizationRequest implements Serializable {

    private static final long serialVersionUID = 144721905123198109L;

    private String clientId;

    private String redirectUri;

    private Set<String> scopes = Collections.emptySet();

    private String state;

    private Set<OidcAuthorizationResponseType> responseTypes = Collections.emptySet();

    private Map<String, String> additionalParameters = Collections.emptyMap();

    private OidcAuthorizationRequest() {
    }

    public Set<OidcAuthorizationResponseType> getResponseTypes() {
        return this.responseTypes;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public String getState() {
        return this.state;
    }

    public Map<String, String> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    /**
     * 根据传入参数，创建授权请求信息
     *
     * @param parameters 其它请求参数
     * @return 授权请求
     */
    public static OidcAuthorizationRequest from(String clientId, String redirectUri, MultiValueMap<String, String> parameters) throws InvalidRequestParameterException {
        OidcAuthorizationRequest request = new OidcAuthorizationRequest();
        request.clientId = clientId;
        request.redirectUri = redirectUri;
        List<String> stateParameters = parameters.get(OAuth2ParameterNames.STATE);
        if (CollectionUtils.isNotEmpty(stateParameters)) {
            if (stateParameters.size() > 1) {
                throw new InvalidRequestParameterException(request, "invalid_request");
            } else {
                request.state = stateParameters.get(0);
            }
        }
        validRequestParameters(parameters, request);
        String responseType = parameters.getFirst(OAuth2ParameterNames.RESPONSE_TYPE);
        if (StringUtils.isNotBlank(responseType)) {
            request.responseTypes = Arrays.stream(StringUtils.split(responseType))
                .map(OidcAuthorizationResponseType::from)
                .collect(Collectors.toSet());

        }

        String scopes = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.isNotBlank(scopes)) {
            request.scopes = new HashSet<>(Arrays.asList(StringUtils.split(scopes)));
        }

        request.additionalParameters = new HashMap<>();
        parameters.forEach((key, values) -> {
            if (isNotAuthorizationRequestParam(key)) {
                request.additionalParameters.put(key, values.get(0));
            }
        });
        return request;
    }

    private static void validRequestParameters(MultiValueMap<String, String> parameters, OidcAuthorizationRequest request) throws InvalidRequestParameterException {
        // 每个参数只允许出现一次
        for (List<String> value : parameters.values()) {
            if (value.size() != 1) {
                // 请求参数异常
                throw new InvalidRequestParameterException(request, "invalid_request");
            }
        }
    }

    private static boolean isNotAuthorizationRequestParam(String param) {
        return !(OAuth2ParameterNames.RESPONSE_TYPE.equals(param) ||
            OAuth2ParameterNames.CLIENT_ID.equals(param) ||
            OAuth2ParameterNames.REDIRECT_URI.equals(param) ||
            OAuth2ParameterNames.SCOPE.equals(param) ||
            OAuth2ParameterNames.STATE.equals(param));
    }
}
