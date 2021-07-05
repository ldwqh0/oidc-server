package org.xyyh.oidc.exception;

/**
 * The authenticated client is not authorized to use this authorization grant type.
 * 某个client请求的grant type不被支持
 */
public class UnauthorizedClientException extends Exception {

    private final String clientId;

    public UnauthorizedClientException() {
        this.clientId = null;
    }

    public UnauthorizedClientException(Throwable e) {
        super("unauthorized_client", e);
        this.clientId = null;
    }

    public UnauthorizedClientException(String clientId) {
        super("unauthorized_client");
        this.clientId = clientId;
    }

    public UnauthorizedClientException(String clientId, Throwable throwable) {
        super("unauthorized_client", throwable);
        this.clientId = clientId;
    }
}
