package org.xyyh.oidc.provider;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.collect.CollectionUtils;
import org.xyyh.oidc.core.OAuth2AuthorizationRequestValidator;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationResponseType;
import org.xyyh.oidc.exception.*;

import java.util.Set;

public class DefaultOAuth2AuthorizationRequestValidator implements OAuth2AuthorizationRequestValidator {


    @Override
    public void validate(OidcAuthorizationRequest request, ClientDetails client) throws InvalidRedirectUriException, InvalidRequestParameterException {

        // 验证redirect uri
        validRedirectUri(request, client);

        // 验证scope
        validScope(request, client);

        // 验证response type
        validResponseType(request, client);

        // 验证pkce
        validPkceRequest(request, client);

    }

    // 验证redirect uri,oauth 2.1 协议规范必须使用字符串匹配校验，不推荐使用通配符校验
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-02#section-4.1.1.1
    private void validRedirectUri(OidcAuthorizationRequest request, ClientDetails client) throws InvalidRedirectUriException {
        Set<String> registeredRedirectUris = client.getRegisteredRedirectUris();
        String redirectUri = request.getRedirectUri();
        if (StringUtils.isBlank(redirectUri)) {
            // 如果请求参数中不包括redirect uri ,判断client的redirect uri 是否唯一
            if (registeredRedirectUris.size() != 1) {
                throw new InvalidRedirectUriException(request);
            }
        } else {
            if (CollectionUtils.isEmpty(registeredRedirectUris) || !registeredRedirectUris.contains(redirectUri)) {
                throw new InvalidRedirectUriException(request);
            }
        }
    }

    private void validScope(OidcAuthorizationRequest request, ClientDetails client) throws InvalidRequestScopeException {
        Set<String> requestScopes = request.getScopes();
        if (CollectionUtils.isNotEmpty(requestScopes)) {
            for (String scope : requestScopes) {
                Set<String> clientScopes = client.getScopes();
                if (!clientScopes.contains(scope)) {
                    throw new InvalidRequestScopeException(request);
                }
            }
        }
    }


    private void validResponseType(OidcAuthorizationRequest request, ClientDetails client) throws UnsupportedResponseTypeException {
        Set<OidcAuthorizationResponseType> requestResponseTypes = request.getResponseTypes();
        Set<AuthorizationGrantType> authorizedGrantTypes = client.getAuthorizedGrantTypes();
        for (OidcAuthorizationResponseType responseType : requestResponseTypes) {
            if (!validResponseType(responseType, authorizedGrantTypes)) {
                throw new UnsupportedResponseTypeException(request);
            }
        }
    }

    /**
     * 验证指定的client的authorizationGrantTypes是否支持特定的responseType
     *
     * @param responseType            待验证的responseType
     * @param authorizationGrantTypes client的authorizationGrantTypes
     * @return 验证成功返回true, 否则返回false
     */
    private boolean validResponseType(OidcAuthorizationResponseType responseType, Set<AuthorizationGrantType> authorizationGrantTypes) {
        // 如果response type=code,要求client必须支持AUTHORIZATION_CODE
        if (OidcAuthorizationResponseType.CODE.equals(responseType)) {
            return authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE);
        }
        // 如果 response type = id_token.要求client必须支持IMPLICIT
        // TODO 这里待优化
        if (OidcAuthorizationResponseType.ID_TOKEN.equals(responseType)) {
            return authorizationGrantTypes.contains(AuthorizationGrantType.IMPLICIT);
        }
        return false;
    }

    /**
     * 验证请求是否符合pkce规范<br>
     * 如果客户端对authorize端点配置为需要pkce验证，则必须进行验证
     *
     * @param client  要验证的客户端
     * @param request 授权请求
     */
    private void validPkceRequest(OidcAuthorizationRequest request, ClientDetails client) throws InvalidCodeChallengeException {
        if (client.isRequirePkce()) {
            String codeChallenge = request.getAdditionalParameters().get("code_challenge");
            if (StringUtils.isBlank(codeChallenge)) {
                throw new InvalidCodeChallengeException(request);
            }
        }
    }
}
