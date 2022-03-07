package org.xzcode.oidc.exception;

import org.xzcode.oidc.endpoint.request.OidcAuthorizationRequest;

public class UnsupportedResponseTypeException extends InvalidRequestParameterException {
    public UnsupportedResponseTypeException(OidcAuthorizationRequest request) {
        super(request, "unsupported_response_type");
    }

    public UnsupportedResponseTypeException(OidcAuthorizationRequest request, String message, Throwable ex) {
        super(request, message, ex);
    }
}
