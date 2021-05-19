package org.xyyh.oidc.core;

import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.endpoint.request.OpenidAuthorizationRequest;
import org.xyyh.oidc.exception.InvalidScopeException;
import org.xyyh.oidc.exception.OpenidRequestValidationException;
import org.xyyh.oidc.exception.UnRegisteredRedirectUriException;
import org.xyyh.oidc.exception.UnsupportedResponseTypeException;

/**
 * OAuth2请求验证器，用户验证请求的正确性
 */
@FunctionalInterface
public interface OAuth2AuthorizationRequestValidator {


    /**
     * 对一个oauth2授权请求进行验证
     *
     * @param request 用户授权请求
     * @param client  连接程序
     */
    void validate(OpenidAuthorizationRequest request, ClientDetails client) throws InvalidScopeException, UnsupportedResponseTypeException, OpenidRequestValidationException, UnRegisteredRedirectUriException;

}
