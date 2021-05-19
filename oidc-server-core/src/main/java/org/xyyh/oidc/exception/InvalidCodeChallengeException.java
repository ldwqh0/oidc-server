package org.xyyh.oidc.exception;

import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

public class InvalidCodeChallengeException extends InvalidRequestParameterException {
    public InvalidCodeChallengeException(OidcAuthorizationRequest request) {
        super(request, "invalid_code_challenge");
    }
}
