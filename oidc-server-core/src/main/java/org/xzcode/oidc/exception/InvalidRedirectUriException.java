package org.xzcode.oidc.exception;

/**
 * redirect uri 异常，当client 配置了多个redirect uri,但授权时没有显示指定redirect uri
 * 或者client没有配置redirect uri
 * 或者授权请求所指定的uri和client配置的redirect uri不匹配时，抛出该异常
 */
public class InvalidRedirectUriException extends Exception {
    private final String clientId;

    public String getClientId() {
        return clientId;
    }

    public InvalidRedirectUriException(String clientId) {
        super("invalid_redirect_uri");
        this.clientId = clientId;
    }

    public InvalidRedirectUriException(String clientId, Throwable ex) {
        super("invalid_redirect_uri", ex);
        this.clientId = clientId;
    }

}
