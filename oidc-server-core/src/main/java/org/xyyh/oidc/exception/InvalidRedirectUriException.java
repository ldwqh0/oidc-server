package org.xyyh.oidc.exception;

import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationResponseType;

/**
 * redirect uri 异常，当client 配置了多个redirect uri,但授权时没有显示指定redirect uri
 * 或者client没有配置redirect uri
 * 或者授权请求所指定的uri和client配置的redirect uri不匹配时，抛出该异常
 */
public class InvalidRedirectUriException extends InvalidRequestException {

    public InvalidRedirectUriException(OidcAuthorizationRequest request) {
        super(request, "invalid_redirect_uri");
    }

    public InvalidRedirectUriException(OidcAuthorizationRequest request, String message, Throwable ex) {
        super(request, message, ex);
    }
}
