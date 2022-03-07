package org.xzcode.oidc.exception;

import org.xzcode.oidc.endpoint.request.OidcAuthorizationRequest;

public class InvalidRequestScopeException extends InvalidRequestParameterException {
    public InvalidRequestScopeException(OidcAuthorizationRequest request) {
        super(request, "invalid_scope");
    }
}
