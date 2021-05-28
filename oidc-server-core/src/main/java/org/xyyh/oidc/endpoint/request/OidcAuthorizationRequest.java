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

    private final String clientId;

    private final String redirectUri;

    private final Set<String> scopes;

    private final String state;

    private final Set<OidcAuthorizationResponseType> responseTypes;

    private final Map<String, String> parameters;

    private OidcAuthorizationRequest(String clientId, String redirectUri, String state, Set<String> scopes, Set<OidcAuthorizationResponseType> responseTypes, Map<String, String> parameters) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.scopes = Collections.unmodifiableSet(scopes);
        this.responseTypes = Collections.unmodifiableSet(responseTypes);
        this.parameters = Collections.unmodifiableMap(parameters);
    }

    private OidcAuthorizationRequest(String clientId, String redirectUri, String state) {
        this(clientId, redirectUri, state, Collections.emptySet(), Collections.emptySet(), Collections.emptyMap());
    }

    private OidcAuthorizationRequest(String clientId, String redirectUri) {
        this(clientId, redirectUri, null);
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

    public Map<String, String> getParameters() {
        return this.parameters;
    }


    /**
     * 根据传入参数，创建授权请求信息
     *
     * @param requestParameters 其它请求参数
     * @return 授权请求
     */
    public static OidcAuthorizationRequest of(String clientId, String redirectUri, MultiValueMap<String, String> requestParameters) throws InvalidRequestParameterException {
        String state = null;
        Set<String> scopes;
        Set<OidcAuthorizationResponseType> responseTypes;

        List<String> stateParameters = requestParameters.get(OAuth2ParameterNames.STATE);
        if (CollectionUtils.isNotEmpty(stateParameters)) {
            if (stateParameters.size() > 1) {
                throw new InvalidRequestParameterException(new OidcAuthorizationRequest(clientId, redirectUri), "invalid_request");
            } else {
                state = stateParameters.get(0);
            }
        }
        if (!validRequestParameters(requestParameters)) {
            throw new InvalidRequestParameterException(new OidcAuthorizationRequest(clientId, redirectUri, state), "invalid_request");
        }
        String scopeParameter = requestParameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.isNotBlank(scopeParameter)) {
            scopes = Arrays.stream(StringUtils.split(scopeParameter)).collect(Collectors.toSet());
        } else {
            scopes = Collections.emptySet();
        }
        String responseTypeParameter = requestParameters.getFirst(OAuth2ParameterNames.RESPONSE_TYPE);
        if (StringUtils.isNotBlank(responseTypeParameter)) {
            responseTypes = Arrays.stream(StringUtils.split(responseTypeParameter))
                .map(OidcAuthorizationResponseType::from)
                .collect(Collectors.toSet());
        } else {
            responseTypes = Collections.emptySet();
        }
        Map<String, String> parameters = requestParameters.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, v -> v.getValue().get(0)));
        return new OidcAuthorizationRequest(
            clientId,
            redirectUri,
            state,
            scopes,
            responseTypes,
            parameters
        );
    }

    private static boolean validRequestParameters(MultiValueMap<String, String> parameters) throws InvalidRequestParameterException {
        // 每个参数只允许出现一次，不运行空参数
        return parameters.values().stream().map(List::size).allMatch(v -> v == 1);
    }
}
