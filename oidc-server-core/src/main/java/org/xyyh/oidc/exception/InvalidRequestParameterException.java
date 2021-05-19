package org.xyyh.oidc.exception;

import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

public class InvalidRequestParameterException extends InvalidRequestException {

    public InvalidRequestParameterException(OidcAuthorizationRequest request, String message) {
        super(request, message);
    }

    public InvalidRequestParameterException(OidcAuthorizationRequest request, String message, Throwable ex) {
        super(request, message, ex);
    }
}
