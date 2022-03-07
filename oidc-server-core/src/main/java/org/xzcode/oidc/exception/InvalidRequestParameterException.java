package org.xzcode.oidc.exception;

import org.xzcode.oidc.endpoint.request.OidcAuthorizationRequest;

public class InvalidRequestParameterException extends InvalidRequestException {

    public InvalidRequestParameterException(OidcAuthorizationRequest request, String message) {
        super(request, message);
    }

    public InvalidRequestParameterException(OidcAuthorizationRequest request, String message, Throwable ex) {
        super(request, message, ex);
    }
}
