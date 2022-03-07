package org.xzcode.oidc.core;

import org.xzcode.oidc.client.ClientDetails;
import org.xzcode.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xzcode.oidc.exception.InvalidRequestParameterException;

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
    void validate(OidcAuthorizationRequest request, ClientDetails client) throws InvalidRequestParameterException;

}
