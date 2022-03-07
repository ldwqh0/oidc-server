package org.xzcode.oidc.exception;

import org.xzcode.oidc.endpoint.request.OidcAuthorizationRequest;

public class InvalidCodeChallengeException extends InvalidRequestParameterException {
    public InvalidCodeChallengeException(OidcAuthorizationRequest request) {
        super(request, "invalid_code_challenge");
    }
}
