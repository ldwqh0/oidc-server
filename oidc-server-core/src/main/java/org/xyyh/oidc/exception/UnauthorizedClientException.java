package org.xyyh.oidc.exception;

import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

public class UnauthorizedClientException extends InvalidRequestException {

    public UnauthorizedClientException(OidcAuthorizationRequest request) {
        super(request, "unauthorized_client");
    }

    public UnauthorizedClientException(OidcAuthorizationRequest request, Throwable ex) {
        super(request, "unauthorized_client", ex);
    }

    public UnauthorizedClientException(OidcAuthorizationRequest request, String message, Throwable ex) {
        super(request, message, ex);
    }
}
