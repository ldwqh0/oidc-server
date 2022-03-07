package org.xzcode.oidc.exception;

import org.xzcode.oidc.endpoint.request.OidcAuthorizationRequest;

public class AccessDeniedException extends InvalidRequestException {
    public AccessDeniedException(OidcAuthorizationRequest request) {
        super(request, "access_denied");
    }
}
