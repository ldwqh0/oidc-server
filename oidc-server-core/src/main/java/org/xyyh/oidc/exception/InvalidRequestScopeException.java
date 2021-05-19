package org.xyyh.oidc.exception;

import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

public class InvalidRequestScopeException extends InvalidRequestParameterException {
    public InvalidRequestScopeException(OidcAuthorizationRequest request) {
        super(request, "invalid_scope");
    }
}
