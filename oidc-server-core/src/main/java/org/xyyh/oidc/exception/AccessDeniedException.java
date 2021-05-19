package org.xyyh.oidc.exception;

import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

public class AccessDeniedException extends InvalidRequestException {
    public AccessDeniedException(OidcAuthorizationRequest request) {
        super(request, "access_denied");
    }
}
