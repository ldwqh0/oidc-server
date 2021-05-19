package org.xyyh.oidc.exception;

import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

/**
 * The request is missing a required parameter,
 * includes an invalid parameter value, includes a parameter more
 * than once, or is otherwise malformed.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-02#section-4.1.2.1">Error Response</a>
 */
public abstract class InvalidRequestException extends Exception {

    private final OidcAuthorizationRequest request;

    public OidcAuthorizationRequest getRequest() {
        return request;
    }

    public InvalidRequestException(final OidcAuthorizationRequest request) {
        super("invalid_request");
        this.request = request;
    }

    public InvalidRequestException(final OidcAuthorizationRequest request, String message) {
        super(message);
        this.request = request;
    }


    public InvalidRequestException(OidcAuthorizationRequest request, String message, Throwable ex) {
        super(message, ex);
        this.request = request;
    }
}
